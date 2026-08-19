import getpass
import pendulum
from functools import lru_cache, wraps
from secrets import token_urlsafe


def timed_lru_cache(lifetime_seconds: int = 300, maxsize: int = 128):
    def wrapper_cache(func):
        func = lru_cache(maxsize=maxsize)(func)
        func.expiration = pendulum.now().add(seconds=lifetime_seconds)

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            if pendulum.now() >= func.expiration:
                func.cache_clear()
                func.expiration = pendulum.now().add(seconds=lifetime_seconds)

            return func(*args, **kwargs)

        return wrapped_func

    return wrapper_cache


def make_token(nbytes: int = 32) -> str:
    return token_urlsafe(nbytes)


def local_username() -> str:
    """Return the username of the account running this process.

    ``getpass.getuser`` checks LOGNAME, USER, LNAME and USERNAME before
    falling back to the password database, so it works on Linux, macOS and
    Windows.

    Because the environment is consulted first, this is trivially overridden
    by exporting LOGNAME. That is a feature for local development: it lets a
    developer act as another seeded user.
    """

    return getpass.getuser()
