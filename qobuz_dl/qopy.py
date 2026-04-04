# Wrapper for Qo-DL Reborn. This is a sligthly modified version
# of qopy, originally written by Sorrow446. All credits to the
# original author.

import configparser
import hashlib
import logging
import os
import time

import requests

from qobuz_dl.exceptions import (
    AuthenticationError,
    IneligibleError,
    InvalidAppIdError,
    InvalidAppSecretError,
    InvalidQuality,
)
from qobuz_dl.color import GREEN, YELLOW

RESET = "Reset your credentials with 'qobuz-dl -r'"

logger = logging.getLogger(__name__)

if os.name == "nt":
    _OS_CONFIG = os.environ.get("APPDATA")
else:
    _OS_CONFIG = os.path.join(os.environ["HOME"], ".config")
_CONFIG_FILE = os.path.join(_OS_CONFIG, "qobuz-dl", "config.ini")


class Client:
    def __init__(self, email, pwd, app_id, secrets):
        logger.info(f"{YELLOW}Logging...")
        self.secrets = secrets
        self.id = str(app_id)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
                "X-App-Id": self.id,
                "Content-Type": "application/json;charset=UTF-8"

            }
        )
        self.base = "https://www.qobuz.com/api.json/0.2/"
        self.sec = None
        self.auth(email, pwd)
        self.cfg_setup()

    def api_call(self, epoint, **kwargs):
        if epoint == "user/login":
            params = {
                "email": kwargs["email"],
                "password": kwargs["pwd"],
                "app_id": self.id,
            }
        elif epoint == "track/get":
            params = {"track_id": kwargs["id"]}
        elif epoint == "album/get":
            params = {"album_id": kwargs["id"]}
        elif epoint == "playlist/get":
            params = {
                "extra": "tracks",
                "playlist_id": kwargs["id"],
                "limit": 500,
                "offset": kwargs["offset"],
            }
        elif epoint == "artist/get":
            params = {
                "app_id": self.id,
                "artist_id": kwargs["id"],
                "limit": 500,
                "offset": kwargs["offset"],
                "extra": "albums",
            }
        elif epoint == "label/get":
            params = {
                "label_id": kwargs["id"],
                "limit": 500,
                "offset": kwargs["offset"],
                "extra": "albums",
            }
        elif epoint == "favorite/getUserFavorites":
            unix = time.time()
            # r_sig = "userLibrarygetAlbumsList" + str(unix) + kwargs["sec"]
            r_sig = "favoritegetUserFavorites" + str(unix) + kwargs["sec"]
            r_sig_hashed = hashlib.md5(r_sig.encode("utf-8")).hexdigest()
            params = {
                "app_id": self.id,
                "user_auth_token": self.uat,
                "type": "albums",
                "request_ts": unix,
                "request_sig": r_sig_hashed,
            }
        elif epoint == "track/getFileUrl":
            unix = time.time()
            track_id = kwargs["id"]
            fmt_id = kwargs["fmt_id"]
            if int(fmt_id) not in (5, 6, 7, 27):
                raise InvalidQuality("Invalid quality id: choose between 5, 6, 7 or 27")
            r_sig = "trackgetFileUrlformat_id{}intentstreamtrack_id{}{}{}".format(
                fmt_id, track_id, unix, kwargs.get("sec", self.sec)
            )
            r_sig_hashed = hashlib.md5(r_sig.encode("utf-8")).hexdigest()
            params = {
                "request_ts": unix,
                "request_sig": r_sig_hashed,
                "track_id": track_id,
                "format_id": fmt_id,
                "intent": "stream",
            }
        else:
            params = kwargs
        r = self.session.get(self.base + epoint, params=params)
        if epoint == "user/login":
            if r.status_code == 401:
                raise AuthenticationError("Invalid credentials.\n" + RESET)
            elif r.status_code == 400:
                raise InvalidAppIdError("Invalid app id.\n" + RESET)
            else:
                logger.info(f"{GREEN}Logged: OK")
        elif (
            epoint in ["track/getFileUrl", "favorite/getUserFavorites"]
            and r.status_code == 400
        ):
            raise InvalidAppSecretError(f"Invalid app secret: {r.json()}.\n" + RESET)

        r.raise_for_status()
        return r.json()

    def auth(self, email, pwd):
        # If pwd looks like a raw password (short, not a long token), try
        # POST login first to exchange it for a user_auth_token.
        if len(pwd) < 60:
            token = self._login_with_password(email, pwd)
            if token:
                pwd = token
                self._save_token(token)
                logger.info(f"{GREEN}Logged in via email/password.")

        self.uat = pwd
        self.session.headers.update({"X-User-Auth-Token": self.uat})
        try:
            resp = self.session.get(self.base + "user/get")
            if resp.status_code == 401:
                raise AuthenticationError(
                    "Token expired or invalid. Run 'qobuz-dl -r' to "
                    "log in again.\n" + RESET
                )
            resp.raise_for_status()
            usr_info = resp.json()
            if "id" not in usr_info:
                raise AuthenticationError(
                    "Token expired or invalid. Run 'qobuz-dl -r' to "
                    "log in again.\n" + RESET
                )
            # Refresh token if the API returns a new one
            new_token = usr_info.get("user_auth_token")
            if new_token and new_token != self.uat:
                self.uat = new_token
                self.session.headers.update({"X-User-Auth-Token": self.uat})
                self._save_token(new_token)
                logger.info(f"{GREEN}Auth token refreshed and saved.")
            # Response is flat — credential is at top level, not under "user"
            cred = usr_info.get("credential", {})
            params = cred.get("parameters")
            if not params:
                raise IneligibleError(
                    "Free accounts are not eligible to download tracks."
                )
            self.label = params.get("short_label", "Unknown")
            logger.info(f"{GREEN}Logged: OK")
            logger.info(f"{GREEN}Membership: {self.label}")
        except (KeyError, requests.exceptions.RequestException) as e:
            raise AuthenticationError(
                f"Auth failed: {e}. Run 'qobuz-dl -r' to log in "
                "again.\n" + RESET
            )

    def _login_with_password(self, email, password):
        """POST form-encoded login to get a user_auth_token.

        Returns the token string on success, or None on failure.
        """
        try:
            resp = self.session.post(
                self.base + "user/login",
                data={"email": email, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                logger.warning(
                    f"{YELLOW}POST login returned {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
                return None
            data = resp.json()
            token = data.get("user_auth_token")
            if not token:
                logger.warning(f"{YELLOW}No token in login response.")
                return None
            return token
        except Exception as e:
            logger.warning(f"{YELLOW}POST login failed: {e}")
            return None

    @staticmethod
    def _save_token(token):
        """Save refreshed auth token back to config.ini."""
        try:
            config = configparser.ConfigParser()
            config.read(_CONFIG_FILE)
            config["DEFAULT"]["password"] = token
            with open(_CONFIG_FILE, "w") as f:
                config.write(f)
        except Exception as e:
            logger.warning(f"{YELLOW}Could not save refreshed token: {e}")

    def multi_meta(self, epoint, key, id, type):
        total = 1
        offset = 0
        while total > 0:
            if type in ["tracks", "albums"]:
                j = self.api_call(epoint, id=id, offset=offset, type=type)[type]
            else:
                j = self.api_call(epoint, id=id, offset=offset, type=type)
            if offset == 0:
                yield j
                total = j[key] - 500
            else:
                yield j
                total -= 500
            offset += 500

    def get_album_meta(self, id):
        return self.api_call("album/get", id=id)

    def get_track_meta(self, id):
        return self.api_call("track/get", id=id)

    def get_track_url(self, id, fmt_id):
        return self.api_call("track/getFileUrl", id=id, fmt_id=fmt_id)

    def get_artist_meta(self, id):
        return self.multi_meta("artist/get", "albums_count", id, None)

    def get_plist_meta(self, id):
        return self.multi_meta("playlist/get", "tracks_count", id, None)

    def get_label_meta(self, id):
        return self.multi_meta("label/get", "albums_count", id, None)

    def search_albums(self, query, limit):
        return self.api_call("album/search", query=query, limit=limit)

    def search_artists(self, query, limit):
        return self.api_call("artist/search", query=query, limit=limit)

    def search_playlists(self, query, limit):
        return self.api_call("playlist/search", query=query, limit=limit)

    def search_tracks(self, query, limit):
        return self.api_call("track/search", query=query, limit=limit)

    def get_favorite_albums(self, offset, limit):
        return self.api_call(
            "favorite/getUserFavorites", type="albums", offset=offset, limit=limit
        )

    def get_favorite_tracks(self, offset, limit):
        return self.api_call(
            "favorite/getUserFavorites", type="tracks", offset=offset, limit=limit
        )

    def get_favorite_artists(self, offset, limit):
        return self.api_call(
            "favorite/getUserFavorites", type="artists", offset=offset, limit=limit
        )

    def get_user_playlists(self, limit):
        return self.api_call("playlist/getUserPlaylists", limit=limit)

    def test_secret(self, sec):
        try:
            self.api_call("track/getFileUrl", id=5966783, fmt_id=5, sec=sec)
            return True
        except InvalidAppSecretError:
            return False

    def cfg_setup(self):
        for secret in self.secrets:
            # Falsy secrets
            if not secret:
                continue

            if self.test_secret(secret):
                self.sec = secret
                break

        if self.sec is None:
            raise InvalidAppSecretError("Can't find any valid app secret.\n" + RESET)
