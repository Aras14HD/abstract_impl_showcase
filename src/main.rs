mod traits {
    use abstract_impl::*;
    use thiserror::Error;
    pub trait TimeType {
        type Time;
    }
    #[abstract_impl(no_dummy)]
    impl TimeUsingType<T> for TimeType {
        type Time = T;
    }
    pub trait AuthTokenType {
        type AuthToken;
    }
    #[abstract_impl(no_dummy)]
    impl AuthTokenUsingType<T> for AuthTokenType {
        type AuthToken = T;
    }
    pub trait DurationType {
        type Duration;
    }
    #[abstract_impl(no_dummy)]
    impl DurationUsingType<T> for DurationType {
        type Duration = T;
    }

    pub trait FromSecs {
        fn from_secs(secs: u64) -> Self;
    }
    impl FromSecs for std::time::Duration {
        fn from_secs(secs: u64) -> Self {
            std::time::Duration::from_secs(secs)
        }
    }
    impl FromSecs for datetime::Duration {
        fn from_secs(secs: u64) -> Self {
            datetime::Duration::of(secs as i64)
        }
    }

    #[derive(Error, Debug)]
    pub enum ValidateAuthTokenErr<Internal, Reason> {
        Invalid(#[from] Reason),
        Internal(Internal),
    }
    pub trait ValidateAuthToken: AuthTokenType {
        type InternalError;
        type InvalidReason;
        fn validate_auth_token(
            &self,
            auth_token: &Self::AuthToken,
        ) -> Result<(), ValidateAuthTokenErr<Self::InternalError, Self::InvalidReason>>;
    }

    pub trait FetchAuthTokenExpiry: AuthTokenType + TimeType {
        type Error;
        fn fetch_auth_token_expiry(
            &self,
            auth_token: &Self::AuthToken,
        ) -> Result<Self::Time, Self::Error>;
    }

    pub trait CurrentTime: TimeType {
        type Error;
        fn current_time() -> Result<Self::Time, Self::Error>;
    }

    #[derive(Error, Debug)]
    pub enum SiteError<Internal> {
        NotFound,
        Internal(#[from] Internal),
    }
    pub trait GetSite {
        type Site;
        type InternalErr;
        fn get_site<'a>(
            &'a self,
            uri: &str,
        ) -> Result<&'a Self::Site, SiteError<Self::InternalErr>>;
    }

    pub trait HasAuth {
        type Token;
        fn has_auth(&self, token: &Self::Token) -> bool;
    }

    #[macro_export]
    macro_rules! impl_AsRef_with_field {
        (<$t:ty> $s:ty {$e:ident}) => {
            impl AsRef<$t> for $s {
                fn as_ref(&self) -> &$t {
                    &self.$e
                }
            }
        };
    }
}

mod impls {
    use super::traits::*;
    use abstract_impl::abstract_impl;
    use datetime::LocalDateTime;
    use std::time::SystemTime;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum ValidateTokenNotExpiredErr<CurrentTimeErr, FetchAuthTokenExpiryErr> {
        CurrentTime(CurrentTimeErr),
        FetchAuthTokenExpiry(FetchAuthTokenExpiryErr),
    }
    #[derive(Debug)]
    pub struct TokenExpired;
    #[abstract_impl(no_dummy)]
    impl ValidateTokenNotExpired for ValidateAuthToken
    where
        Self: CurrentTime + FetchAuthTokenExpiry,
        <Self as TimeType>::Time: Ord,
    {
        type InternalError = ValidateTokenNotExpiredErr<
            <Self as CurrentTime>::Error,
            <Self as FetchAuthTokenExpiry>::Error,
        >;
        type InvalidReason = TokenExpired;
        fn validate_auth_token(
            &self,
            auth_token: &Self::AuthToken,
        ) -> Result<(), ValidateAuthTokenErr<Self::InternalError, Self::InvalidReason>> {
            let now = Self::current_time()
                .map_err(Self::InternalError::CurrentTime)
                .map_err(ValidateAuthTokenErr::Internal)?;

            let token_expiry = self
                .fetch_auth_token_expiry(auth_token)
                .map_err(Self::InternalError::FetchAuthTokenExpiry)
                .map_err(ValidateAuthTokenErr::Internal)?;

            if token_expiry > now {
                Ok(())
            } else {
                Err(ValidateAuthTokenErr::Invalid(TokenExpired))
            }
        }
    }

    pub type Void = std::convert::Infallible;
    #[abstract_impl(no_dummy)]
    impl UseLocalDateTime for CurrentTime
    where
        Self: TimeType<Time = LocalDateTime>,
    {
        type Error = Void;
        fn current_time() -> Result<LocalDateTime, Void> {
            Ok(LocalDateTime::now())
        }
    }
    #[abstract_impl(no_dummy)]
    impl UseSystemTime for CurrentTime
    where
        Self: TimeType<Time = SystemTime>,
    {
        type Error = Void;
        fn current_time() -> Result<SystemTime, Void> {
            Ok(SystemTime::now())
        }
    }

    #[derive(Error, Debug)]
    pub enum SiteAuthError<Internal> {
        Forbidden,
        Internal(#[from] Internal),
    }
    #[abstract_impl]
    impl GetSiteWithAuth<SiteStore, S> for GetSite
    where
        SiteStore: GetSite + 'static,
        <SiteStore as GetSite>::Site: AsRef<S> + HasAuth,
        Self: AsRef<SiteStore> + AsRef<<<SiteStore as GetSite>::Site as HasAuth>::Token>,
    {
        type Site = S;
        type InternalErr = SiteAuthError<<SiteStore as GetSite>::InternalErr>;
        fn get_site<'a>(
            &'a self,
            uri: &str,
        ) -> Result<&'a Self::Site, SiteError<Self::InternalErr>> {
            let site = AsRef::<SiteStore>::as_ref(self)
                .get_site(uri)
                .map_err(|e| match e {
                    SiteError::Internal(i) => SiteError::Internal(SiteAuthError::from(i)),
                    SiteError::NotFound => SiteError::NotFound,
                })?;
            if !site.has_auth(self.as_ref()) {
                return Err(SiteError::Internal(SiteAuthError::Forbidden));
            };
            Ok(site.as_ref())
        }
    }
}

use datetime::LocalDateTime;
use impls::*;
use std::time::SystemTime;
use std::{collections::BTreeMap, env::args, sync::Arc};
use traits::*;

// Everything can be changed here! Super generic
type Token = Option<Arc<str>>;
type URI = &'static str;
type Content = &'static str;
type Time = LocalDateTime;
type Duration = datetime::Duration;
impl_UseLocalDateTime!(MockApp);

impl_ValidateTokenNotExpired!(MockApp);

pub struct MockApp {
    pub auth_tokens_store: BTreeMap<Token, <Self as TimeType>::Time>,
    pub sites: BTreeMap<URI, Site>,
}
impl GetSite for MockApp {
    type Site = Site;
    type InternalErr = std::convert::Infallible;
    fn get_site<'a>(&'a self, uri: &str) -> Result<&'a Self::Site, SiteError<Self::InternalErr>> {
        self.sites.get(uri).ok_or(SiteError::NotFound)
    }
}
pub struct Site {
    pub content: Content,
    pub privilege: Privilege,
}
impl_AsRef_with_field!(<Content> Site {content});
impl HasAuth for Site {
    type Token = Token;
    fn has_auth(&self, token: &Self::Token) -> bool {
        match &self.privilege {
            Privilege::None => true,
            Privilege::Whitelist(l) => l.contains(token),
            Privilege::Blacklist(l) => !l.contains(token) && token != &Token::default(),
        }
    }
}
pub enum Privilege {
    None,
    Whitelist(Vec<Token>),
    Blacklist(Vec<Token>),
}

struct AuthedMockApp {
    token: Token,
    app: std::sync::Arc<MockApp>,
}
impl_AsRef_with_field!(<MockApp> AuthedMockApp {app});
impl_AsRef_with_field!(<Token> AuthedMockApp {token});
impl_GetSiteWithAuth!(<MockApp, Content> AuthedMockApp);
impl AuthedMockApp {
    fn new(
        app: Arc<MockApp>,
        token: Token,
    ) -> (
        Self,
        Option<
            ValidateAuthTokenErr<
                <MockApp as ValidateAuthToken>::InternalError,
                <MockApp as ValidateAuthToken>::InvalidReason,
            >,
        >,
    ) {
        let (token, err) = match app.validate_auth_token(&token) {
            Ok(_) => (token, None),
            Err(err) => (Token::default(), Some(err)),
        };
        (AuthedMockApp { token, app }, err)
    }
}

impl_TimeUsingType!(<Time> MockApp);
impl_DurationUsingType!(<Duration> MockApp);
impl_AuthTokenUsingType!(<Token> MockApp);

#[derive(Debug)]
pub struct MissingToken;
impl FetchAuthTokenExpiry for MockApp {
    type Error = MissingToken;
    fn fetch_auth_token_expiry(
        &self,
        auth_token: &Self::AuthToken,
    ) -> Result<Self::Time, Self::Error> {
        if auth_token == &Self::AuthToken::default() {
            return Ok(
                Self::current_time().unwrap() + <Self as DurationType>::Duration::from_secs(60 * 5)
            );
        }
        self.auth_tokens_store
            .get(auth_token)
            .cloned()
            .ok_or(MissingToken)
    }
}

fn main() {
    let app = Arc::new(MockApp {
        auth_tokens_store: BTreeMap::from([
            (
                Some("Test".into()),
                MockApp::current_time().unwrap()
                    + <MockApp as DurationType>::Duration::from_secs(1),
            ),
            (
                Some("Other".into()),
                MockApp::current_time().unwrap()
                    + <MockApp as DurationType>::Duration::from_secs(1000),
            ),
            (
                Some("You".into()),
                MockApp::current_time().unwrap()
                    + <MockApp as DurationType>::Duration::from_secs(0),
            ),
        ]),
        sites: BTreeMap::from([
            (
                "/".into(),
                Site {
                    content: "Hi! This is our Site",
                    privilege: Privilege::None,
                },
            ),
            (
                "/priv".into(),
                Site {
                    content: "This is private data!",
                    privilege: Privilege::Whitelist(vec![Some("Test".into())]),
                },
            ),
            (
                "/not-him".into(),
                Site {
                    content: "This is semi private data!",
                    privilege: Privilege::Blacklist(vec![Some("Test".into())]),
                },
            ),
        ]),
    });
    let mut args = args().skip(1);
    let token = args.next().map(Into::into);
    let route = args.next().unwrap_or("/".into());

    // std::thread::sleep(Duration::from_secs(1));

    let (app, auth_err) = AuthedMockApp::new(app, token);

    if let Some(auth_err) = auth_err {
        println!("{auth_err:?}")
    };

    let site = app.get_site(&route).unwrap();
    println!("{site}");
}
