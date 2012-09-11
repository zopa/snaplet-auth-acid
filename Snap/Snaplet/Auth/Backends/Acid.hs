{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Snap.Snaplet.Auth.Backends.Acid 
         ( initAcidAuthManager
         , getAllLogins 
         ) where

import           Snap
import           Snap.Snaplet.Auth
import           Snap.Snaplet.Session
--import           Snap.Snaplet.Session.Common

import           Control.Error
import           Control.Monad.CatchIO (throw)
import           Control.Monad.Reader (ask)
import           Data.Aeson (Value, encode, decode)
import           Data.Acid
import           Data.Attoparsec.Number (Number)
import           Data.SafeCopy
import qualified Data.Serialize as S (get, put)
import           Data.Hashable (Hashable)
import qualified Data.HashMap.Strict as H
import           Data.Text (Text, pack)
import           Data.Time
import           Data.Typeable (Typeable)
import qualified Data.Vector as V (Vector, toList, fromList)
import           Web.ClientSession

type UserLogin = Text
type RToken    = Text

data UserStore = UserStore 
                   { users      :: H.HashMap UserId AuthUser
                   , loginIndex :: H.HashMap UserLogin UserId
                   , tokenIndex :: H.HashMap RToken UserId
                   , uidCount   :: Int
                   } deriving (Typeable)

instance (SafeCopy a, SafeCopy b, Eq a, Hashable a) => 
    SafeCopy (H.HashMap a b) where
      getCopy = contain $ fmap H.fromList safeGet
      putCopy = contain . safePut . H.toList

instance (SafeCopy a) => SafeCopy (V.Vector a) where
      getCopy = contain $ fmap V.fromList safeGet
      putCopy = contain . safePut . V.toList

deriving instance Typeable AuthUser

$(deriveSafeCopy 0 'base ''Number)
$(deriveSafeCopy 0 'base ''Value)
$(deriveSafeCopy 0 'base ''Password)
$(deriveSafeCopy 0 'base ''Role) 
$(deriveSafeCopy 0 'base ''BackendError)
$(deriveSafeCopy 0 'base ''AuthUser)
$(deriveSafeCopy 0 'base ''UserId)
$(deriveSafeCopy 0 'base ''UserStore)
 
emptyUS :: UserStore
emptyUS = UserStore H.empty H.empty H.empty 0

saveU :: AuthUser
      -> UTCTime
      -> Update UserStore (Either BackendError AuthUser)
saveU u now = do
    UserStore us li ti n <- get
    case (H.lookup (userLogin u) li) of
      Just v | Just v /= userId u -> return $ Left DuplicateLogin
      _  -> do
          let uid = Just . maybe ((UserId . pack.show) (n+1)) id $ userId u
              old = userId u >>= flip H.lookup us
              n'  = maybe (n+1) (const n) 
                  $ userId u >>= flip H.lookup us
              u'  = u { userUpdatedAt = Just now, userId = uid }
              us' = fromMaybe us $ H.insert <$> uid <*> pure u' <*> pure us
              oldL = userLogin <$> old
              oldT = userRememberToken =<< old
              li' = fromMaybe li $ H.insert <$> pure (userLogin u) <*> uid 
                  <*> ( H.delete <$> oldL <*> pure li )
              ti' = fromMaybe ti $ H.insert <$> (userRememberToken u) <*> uid 
                  <*> ( H.delete <$> oldT <*> pure ti )
              new = UserStore us' li' ti' n'
          put new
          return $ Right u'

byUserId :: UserId -> Query UserStore (Maybe AuthUser)
byUserId uid = do
    UserStore us _ _ _ <- ask
    return $ H.lookup uid us

byLogin :: UserLogin -> Query UserStore (Maybe AuthUser)
byLogin l = do
    UserStore _ li _ _ <- ask
    maybe (return Nothing) byUserId $ H.lookup l li

byRememberToken :: RToken -> Query UserStore (Maybe AuthUser)
byRememberToken tok = do
    UserStore _ _ ti _<- ask
    maybe (return Nothing) byUserId $ H.lookup tok ti

destroyU :: AuthUser -> Update UserStore ()
destroyU au = do
    case (userId au) of
      Nothing  -> return ()
      Just uid -> do
          UserStore us li ti n <- get
          storedUser <- runQuery $ byUserId uid
          let li' = fromMaybe li $
                  H.delete . userLogin <$> storedUser <*> pure li
              ti' = fromMaybe ti $
                  H.delete <$> (userRememberToken =<< storedUser) <*> pure ti
          put $ UserStore (H.delete uid us) li' ti' n

allLogins :: Query UserStore [UserLogin]
allLogins = do
    UserStore _ li _ _ <- ask
    return $ H.keys li

$(makeAcidic ''UserStore [ 'saveU
                         , 'byUserId
                         , 'byLogin
                         , 'byRememberToken
                         , 'destroyU
                         , 'allLogins
                         ] )

instance IAuthBackend (AcidState UserStore) where
    save                           = acidSave
    lookupByUserId acid uid        = query  acid $ ByUserId uid
    lookupByLogin  acid l          = query  acid $ ByLogin l
    lookupByRememberToken acid tok = query  acid $ ByRememberToken tok
    destroy acid au                = update acid $ DestroyU au
    
acidSave :: (AcidState UserStore) -> AuthUser -> IO AuthUser
acidSave acid u = do
    now    <- getCurrentTime
    result <- update acid $ SaveU u now
    case result of
        Left e  -> throw e
        Right u -> return u
 
initAcidAuthManager :: AuthSettings
                    -> Lens b (Snaplet SessionManager)
                    -> SnapletInit b (AuthManager b)
initAcidAuthManager s lns = do
    makeSnaplet 
      "AcidStateAuthManager"
      "A snaplet providing user authentication using an Acid State backend"
      Nothing $ do
          rng  <- liftIO mkRNG
          key  <- liftIO $ getKey (asSiteKey s)
          dir  <- getSnapletFilePath
          acid <- liftIO $ openLocalStateFrom dir emptyUS
          return $! AuthManager 
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
                
getAllLogins :: (AcidState UserStore) -> Handler b (AuthManager v) [Text]
getAllLogins acid = liftIO $ query acid AllLogins
    
    
