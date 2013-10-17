{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}

module Snap.Snaplet.Auth.Backends.Acid where

import           Control.Error
import           Control.Exception hiding (Handler)
import           Control.Monad.CatchIO (throw)
import           Control.Monad.Reader (ask)
import           Data.Acid
import           Data.Aeson (Value, encode, decode)
import           Data.Attoparsec.Number (Number)
import           Control.Lens
import qualified Data.HashMap.Strict as H
import           Data.Hashable (Hashable)
import           Data.Maybe
import           Data.SafeCopy
import qualified Data.Serialize as S (get, put)
import           Data.Text (Text, pack)
import           Data.Time
import           Data.Typeable (Typeable)
import qualified Data.Vector as V (Vector, toList, fromList)
import           Snap
import           Snap.Snaplet.Auth
import           Snap.Snaplet.Session
import           System.Directory
import           System.IO.Error hiding (catch)
import           Web.ClientSession
import           Snap.Util.FileServe
import           System.FilePath ((</>))

------------------------------------------------------------------------------
type UserLogin = Text
type RToken    = Text


------------------------------------------------------------------------------
data UserStore = UserStore
                   { _users      :: H.HashMap UserId AuthUser
                   , _loginIndex :: H.HashMap UserLogin UserId
                   , _tokenIndex :: H.HashMap RToken UserId
                   , _nextUserId :: Int
                   } deriving (Typeable)

makeLenses ''UserStore


------------------------------------------------------------------------------
instance (SafeCopy a, SafeCopy b, Eq a, Hashable a) =>
    SafeCopy (H.HashMap a b) where
      getCopy = contain $ fmap H.fromList safeGet
      putCopy = contain . safePut . H.toList


------------------------------------------------------------------------------
instance (SafeCopy a) => SafeCopy (V.Vector a) where
      getCopy = contain $ fmap V.fromList safeGet
      putCopy = contain . safePut . V.toList


------------------------------------------------------------------------------
deriving instance Typeable AuthUser


------------------------------------------------------------------------------
$(deriveSafeCopy 0 'base ''Number)
$(deriveSafeCopy 0 'base ''Value)
$(deriveSafeCopy 0 'base ''Password)
$(deriveSafeCopy 0 'base ''Role)
$(deriveSafeCopy 0 'base ''AuthFailure)
$(deriveSafeCopy 0 'base ''AuthUser)
$(deriveSafeCopy 0 'base ''UserId)
$(deriveSafeCopy 0 'base ''UserStore)


------------------------------------------------------------------------------
emptyUS :: UserStore
emptyUS = UserStore H.empty H.empty H.empty 0


------------------------------------------------------------------------------
saveAuthUser :: AuthUser
             -> UTCTime
             -> Update UserStore (Either AuthFailure AuthUser)
saveAuthUser user utcTime = do
  let authUserId = userId user
  case authUserId of
    Just id -> saveExistingUser user id utcTime
    Nothing -> saveNewUser user utcTime


------------------------------------------------------------------------------
saveNewUser :: AuthUser
            -> UTCTime
            -> Update UserStore (Either AuthFailure AuthUser)
saveNewUser user currentTime = do
  loginCache <- use loginIndex
  if isJust $ H.lookup (userLogin user) loginCache
    then return $ Left DuplicateLogin
    else do
      uid <- liftM (UserId . pack . show) $ use nextUserId
      nextUserId += 1
      let user' = user { userUpdatedAt = Just currentTime, userId = Just uid }
      updateUserCache user' uid
      updateLoginCache (userLogin user') uid
      updateTokenCache (userRememberToken user) uid
      return $ Right user'


------------------------------------------------------------------------------
saveExistingUser :: AuthUser
                 -> UserId
                 -> UTCTime
                 -> Update UserStore (Either AuthFailure AuthUser)
saveExistingUser user userId currentTime = do
  loginCache <- use loginIndex
  if Just userId /= H.lookup (userLogin user) loginCache
     then return $ Left DuplicateLogin
     else do
       userCache  <- use users

       let oldUser = fromMaybe user $ H.lookup userId userCache
       loginIndex %= H.delete (userLogin oldUser)
       tokenIndex %= deleteIfJust (userRememberToken oldUser)

       let user' = user { userUpdatedAt = Just currentTime }
       updateUserCache user' userId
       updateLoginCache (userLogin user') userId
       updateTokenCache (userRememberToken user) userId

       return $ Right user


------------------------------------------------------------------------------
deleteIfJust :: (Hashable a, Eq a) => Maybe a -> H.HashMap a b -> H.HashMap a b
deleteIfJust (Just val) hash = H.delete val hash
deleteIfJust Nothing hash    = hash

------------------------------------------------------------------------------
updateUserCache :: (MonadState UserStore m) => AuthUser -> UserId ->  m ()
updateUserCache user uid = users %= H.insert uid user


------------------------------------------------------------------------------
updateLoginCache :: (MonadState UserStore m) => Text-> UserId ->  m ()
updateLoginCache login uid = loginIndex %= H.insert login uid


------------------------------------------------------------------------------
updateTokenCache :: (MonadState UserStore m) => Maybe Text -> UserId ->  m ()
updateTokenCache (Just token) uid = tokenIndex %= H.insert token uid
updateTokenCache Nothing _        = return ()


------------------------------------------------------------------------------
byUserId :: UserId -> Query UserStore (Maybe AuthUser)
byUserId uid = do
    UserStore us _ _ _ <- ask
    return $ H.lookup uid us


------------------------------------------------------------------------------
byLogin :: UserLogin -> Query UserStore (Maybe AuthUser)
byLogin l = do
    UserStore _ li _ _ <- ask
    maybe (return Nothing) byUserId $ H.lookup l li


------------------------------------------------------------------------------
byRememberToken :: RToken -> Query UserStore (Maybe AuthUser)
byRememberToken tok = do
    UserStore _ _ ti _<- ask
    maybe (return Nothing) byUserId $ H.lookup tok ti


------------------------------------------------------------------------------
destroyU :: AuthUser -> Update UserStore ()
destroyU au =
    case userId au of
      Nothing  -> return ()
      Just uid -> do
          UserStore us li ti n <- get
          storedUser <- liftQuery $ byUserId uid
          let li' = fromMaybe li $
                  H.delete . userLogin <$> storedUser <*> pure li
              ti' = fromMaybe ti $
                  H.delete <$> (userRememberToken =<< storedUser) <*> pure ti
          put $ UserStore (H.delete uid us) li' ti' n


------------------------------------------------------------------------------
allLogins :: Query UserStore [UserLogin]
allLogins = do
    UserStore _ li _ _ <- ask
    return $ H.keys li


------------------------------------------------------------------------------
$(makeAcidic ''UserStore [ 'saveAuthUser
                         , 'byUserId
                         , 'byLogin
                         , 'byRememberToken
                         , 'destroyU
                         , 'allLogins
                         ] )


------------------------------------------------------------------------------
instance IAuthBackend (AcidState UserStore) where
    save                           = acidSave
    lookupByUserId acid uid        = query  acid $ ByUserId uid
    lookupByLogin  acid l          = query  acid $ ByLogin l
    lookupByRememberToken acid tok = query  acid $ ByRememberToken tok
    destroy acid au                = update acid $ DestroyU au


------------------------------------------------------------------------------
acidSave :: AcidState UserStore -> AuthUser -> IO (Either AuthFailure AuthUser)
acidSave acid user = do
    now    <- getCurrentTime
    update acid $ SaveAuthUser user now


------------------------------------------------------------------------------
initAcidAuthManager :: AuthSettings
                    -> SnapletLens b SessionManager
                    -> SnapletInit b (AuthManager b)
initAcidAuthManager s lns =
    makeSnaplet
      "AcidStateAuthManager"
      "A snaplet providing user authentication using an Acid State backend"
      Nothing $ do
          removeResourceLockOnUnload
          rng  <- liftIO mkRNG
          key  <- liftIO $ getKey (asSiteKey s)
          dir  <- getSnapletFilePath
          acid <- liftIO $ openLocalStateFrom dir emptyUS
          return AuthManager
                   { backend               = acid
                   , session               = lns
                   , activeUser            = Nothing
                   , minPasswdLen          = asMinPasswdLen s
                   , rememberCookieName    = asRememberCookieName s
                   , rememberPeriod        = asRememberPeriod s
                   , siteKey               = key
                   , lockout               = asLockout s
                   , randomNumberGenerator = rng
                   }


------------------------------------------------------------------------------
removeResourceLockOnUnload :: Initializer b v ()
removeResourceLockOnUnload = do
  path <- getSnapletFilePath
  let resourceLockPath = path </> "open.lock"
  onUnload $ removeIfExists resourceLockPath


------------------------------------------------------------------------------
removeIfExists :: FilePath -> IO ()
removeIfExists fileName = removeFile fileName `catch` handleExists
  where handleExists e
          | isDoesNotExistError e = return ()
          | otherwise = throwIO e


------------------------------------------------------------------------------
getAllLogins :: AcidState UserStore -> Handler b (AuthManager v) [Text]
getAllLogins acid = liftIO $ query acid AllLogins
