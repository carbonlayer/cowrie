# Copyright 2021 Diego Parrilla Santamaria
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Cowrie plugin for reporting login attempts via the CarbonLayer.io Report API.

"CarbonLayer.io is a tool to track and detect attacks" <https://carbonlayer.io/>
"""


__author__ = "Diego Parrilla Santamaria"
__version__ = "0.0.1"

import datetime

from typing import Set
from pathlib import Path

from cowrie.core import output
from cowrie.core.config import CowrieConfig

from treq import post

from twisted.internet import defer, reactor, threads
from twisted.python import log
from twisted.web import http

# Buffer flush frequency (in minutes)
BUFFER_FLUSH_FREQUENCY: int = 1

# Buffer flush max size
BUFFER_FLUSH_MAX_SIZE: int = 1000

# API URL
CARBONLAYER_REPORT_URL: str = "http://report.infra.carbonlayer.io/v1/ip"

# Default Time To Live (TTL) in the CarbonLayer.io private blocklist. In minutes.
CARBONLAYER_DEFAULT_TTL: int = 86400

# Default category to store the ip address.
CARBONLAYER_DEFAULT_CATEGORY: str = "ABUSE"


class HTTPClient:
    """
    HTTP client to report the IP adress set
    """

    def __init__(self, bearer_token: str = None):
        self.headers = {
            "User-Agent": "Cowrie Honeypot Carbonlayer.io output plugin",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "bearer": bearer_token,
        }

    def report(self, ip_set: Set[str], category: str = None, ttl: int = 0):
        payload: dict = {"addresses": list(ip_set), "type": category, "ttl": ttl}
        self._post(payload)

    @defer.inlineCallbacks
    def _post(self, payload: dict):
        try:
            response = yield post(
                url=CARBONLAYER_REPORT_URL,
                headers=self.headers,
                json=payload,
            )

        except Exception as e:
            log.msg(
                eventid="cowrie.carbonlayer.reportfail",
                format="Carbonlayer.io output plugin failed when reporting the payload %(payload)s. "
                "Exception raised: %(exception)s.",
                payload=str(payload),
                exception=repr(e),
            )
            return

        if response.code != http.OK:
            reason = yield response.text()
            log.msg(
                eventid="cowrie.carbonlayer.reportfail",
                format="Carbonlayer output plugin failed to report the payload %(payload)s. Returned the\
 HTTP status code %(response)s. Reason: %(reason)s.",
                payload=str(payload),
                response=response.code,
                reason=reason,
            )
        else:
            log.msg(
                eventid="cowrie.carbonlayer.reportedipset",
                format="Carbonlayer output plugin successfully reported %(payload)s.",
                payload=str(payload),
            )
        return


class Output(output.Output):
    def start(self):
        self.default_ttl = CowrieConfig.getint(
            "output_carbonlayer", "default_ttl", fallback=CARBONLAYER_DEFAULT_TTL
        )
        self.default_category = CowrieConfig.get(
            "output_carbonlayer",
            "default_category",
            fallback=CARBONLAYER_DEFAULT_CATEGORY,
        )
        self.bearer_token = CowrieConfig.get("output_carbonlayer", "bearer_token")

        self.last_report: int = -1
        self.report_bucket: int = BUFFER_FLUSH_MAX_SIZE
        self.ip_set: Set[str] = set()

        self.http_client = HTTPClient(self.bearer_token)
        log.msg(
            eventid="cowrie.carbonlayer.reporterinitialized",
            format="Carbonlayer output plugin successfully initialized. Category=%(category)s. TTL=%(ttl)s",
            category=self.default_category,
            ttl=self.default_ttl,
        )

    def stop(self):
        log.msg(
            eventid="cowrie.carbonlayer.reporterterminated",
            format="Carbonlayer output plugin successfully terminated. Bye!",
        )

    def write(self, ev):
        if ev["eventid"].rsplit(".", 1)[0] in [
            "cowrie.login",
            "cowrie.session",
        ]:
            source_ip: str = ev["src_ip"]
            self.ip_set.add(source_ip)
            #            log.msg(
            #                eventid="cowrie.carbonlayer.queuedip",
            #                format="Carbonlayer output plugin enqueued the IP %(ip)s to report.",
            #                ip=source_ip,
            #            )

            if self.last_report == -1:
                # Never execute in this cycle. Store timestamp of the first element.
                self.last_report = int(datetime.datetime.utcnow().timestamp())
            self.report_bucket -= 1
            if (
                self.report_bucket == 0
                or (int(datetime.datetime.utcnow().timestamp()) - self.last_report)
                > BUFFER_FLUSH_FREQUENCY * 60
            ):
                # Flush the ip_set if 1000 ips counted or more than 10 minutes since last flush
                self.http_client.report(
                    ip_set=self.ip_set,
                    category=self.default_category,
                    ttl=self.default_ttl,
                )
                self.ip_set = set()
                self.report_bucket = BUFFER_FLUSH_MAX_SIZE
                self.last_report = -1
