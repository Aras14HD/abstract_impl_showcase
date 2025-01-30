mod traits {
    use abstract_impl::abstract_impl;
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

    #[abstract_impl]
    impl TimeUsingLocal for TimeType {
        type Time = LocalDateTime;
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
use std::{collections::BTreeMap, env::args, sync::Arc, time::Duration};
use traits::*;

type Token = String;
pub struct MockApp {
    pub auth_tokens_store: BTreeMap<Token, LocalDateTime>,
    pub sites: BTreeMap<String, Site>,
}
impl GetSite for MockApp {
    type Site = Site;
    type InternalErr = std::convert::Infallible;
    fn get_site<'a>(&'a self, uri: &str) -> Result<&'a Self::Site, SiteError<Self::InternalErr>> {
        self.sites.get(uri).ok_or(SiteError::NotFound)
    }
}
pub struct Site {
    pub content: String,
    pub privilege: Privilege,
}
impl_AsRef_with_field!(<String> Site {content});
impl HasAuth for Site {
    type Token = Token;
    fn has_auth(&self, token: &Self::Token) -> bool {
        match &self.privilege {
            Privilege::None => true,
            Privilege::Whitelist(l) => l.contains(token),
            Privilege::Blacklist(l) => !l.contains(token) && token != "",
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
impl_GetSiteWithAuth!(<MockApp, String> AuthedMockApp);
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
            Err(err) => (String::new(), Some(err)),
        };
        (AuthedMockApp { token, app }, err)
    }
}

impl_UseLocalDateTime!(MockApp);
impl_TimeUsingLocal!(MockApp);
impl_AuthTokenUsingType!(<String> MockApp);
impl_ValidateTokenNotExpired!(MockApp);

#[derive(Debug)]
pub struct MissingToken;
impl FetchAuthTokenExpiry for MockApp {
    type Error = MissingToken;
    fn fetch_auth_token_expiry(
        &self,
        auth_token: &Self::AuthToken,
    ) -> Result<Self::Time, Self::Error> {
        if auth_token == &Self::AuthToken::default() {
            return Ok(LocalDateTime::now().add_seconds(60 * 5));
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
            ("Test".to_string(), LocalDateTime::now().add_seconds(1)),
            ("Other".to_string(), LocalDateTime::now().add_seconds(1000)),
            ("You".to_string(), LocalDateTime::now().add_seconds(0)),
        ]),
        sites: BTreeMap::from([
            (
                "/".to_string(),
                Site {
                    content: "Hi! This is our Site".to_string(),
                    privilege: Privilege::None,
                },
            ),
            (
                "/priv".to_string(),
                Site {
                    content: "This is private data!".to_string(),
                    privilege: Privilege::Whitelist(vec!["Test".to_string()]),
                },
            ),
            (
                "/not-him".to_string(),
                Site {
                    content: "This is semi private data!".to_string(),
                    privilege: Privilege::Blacklist(vec!["Test".to_string()]),
                },
            ),
        ]),
    });
    let mut args = args().skip(1);
    let token = args.next().unwrap_or("".to_string());
    let route = args.next().unwrap_or("/".to_string());

    // std::thread::sleep(Duration::from_secs(1));

    let (app, auth_err) = AuthedMockApp::new(app, token);

    if let Some(auth_err) = auth_err {
        println!("{auth_err:?}")
    };

    let site = app.get_site(&route).unwrap();
    println!("{site}");
}
