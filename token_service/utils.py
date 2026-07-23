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
