# Restricted Access

Implement geographic access restrictions in front of Nginx: automatically update the MaxMind GeoLite2/GeoIP2 database to block requests from blacklisted regions. For allowed regions, access is granted only after the request has been verified by the target site.

> The detection service should listen exclusively on the loopback address. Nginx’s `auth_request` module handles the actual blocking of requests. Do not expose the detection port or the origin server to the public internet.

> ***Note: This project does not implement functionality to detect VPNs/proxies.***

## How does it work?

1. For a protected location, an internal request is first made to `/_ra/verify`. If no valid access token exists, or if the geographic verification fails, a 401 status code is returned.
2. Nginx redirects the visitor to `/_ra/gate`. The detection service only trusts the `X-Real-IP` header when it originates from a trusted proxy and matches the `$remote_addr` value recorded by Nginx.
3. If the IP address is blacklisted, cannot be geolocated, is not found in the (potentially outdated) database, or is deemed untrustworthy, the system returns an "Access denied from your current location" message. In such cases, no cookie is issued, and any redirect parameters provided by the visitor are ignored.
4. If the location is permitted, a one-time-use access token—valid for only a few seconds and cryptographically bound to the specific IP address—is issued. The user is then redirected (via 302) to the configured `callback_url`.
5. The target site’s `/_ra/callback` endpoint submits the access token to the detection service for validation. Once verified, a cookie is set with the `HttpOnly`, `Secure`, and `SameSite=Lax` attributes (with no `Domain` attribute specified), and the user is redirected to a pre-configured path within the site.
6. For all subsequent content requests, the system re-validates the cookie’s signature, expiration status, IP binding, and geographic location. If the geographic assessment changes, the existing cookie is immediately invalidated.

This approach is similar to the verification mechanism used by Cloudflare for bot detection: 
redirects or parameters held solely by the browser are not considered sufficient proof of authorization; 
the target site must independently verify the request with the detection service. Both the access token and the cookie are signed using a server-side-only secret key, ensuring they are not interchangeable.
Furthermore, any redirect destinations (such as a `next` parameter in the query string) are ignored.

## When Restrictions May Fail

GeoIP relies on the public-facing IP address observed, not the user's actual physical location. 
Traffic routed through VPNs, proxies, or hosting-based exit nodes located in permitted regions will be granted access based on the location of those exit nodes. 
This is a limitation inherent to the nature of IP-based geolocation; it cannot be resolved by the service itself, 
nor should one attempt to "identify" such exit nodes by inspecting additional request headers.

The following scenarios will cause restrictions to be bypassed. These must be addressed during deployment—they cannot be mitigated by the application itself once the system is running:

- A `location` block is configured with `auth_request off` or `satisfy any`.
- The origin server’s port is accessible directly, bypassing Nginx.
- The signing key is compromised, and an attacker is also able to manipulate the visitor's IP address as seen by Nginx. (Note: A compromised key alone cannot turn a blocked region into a permitted one, as the location is re-verified during every `/verify` request.)
- If the `ipv4_prefix` (or `ipv6_prefix`) is configured with a broader scope (i.e., a smaller prefix length) and a session cookie remains valid, other clients sharing the same NAT or IP prefix may inherit the access credentials associated with that address range. The default settings are `/32` for IPv4 and `/128` for IPv6.

## Preparing MaxMind

Register with MaxMind and accept the GeoLite2 license to obtain your Account ID and License Key. 
The current download interface uses [Basic Authentication with your Account ID and License Key](https://dev.maxmind.com/geoip/updating-databases/); 
you cannot simply include the license key in the URL. The application will only send the credentials to `download.maxmind.com`; 
if a redirect occurs to an object storage service on a different host, the `Authorization` header will be stripped.

The default database is `GeoLite2-Country`. You may also use `GeoLite2-City`, `GeoIP2-Country`, or `GeoIP2-City`. If you use GeoLite2, please ensure that the attribution required by MaxMind is displayed on your site.

Downloads are restricted to the hosts `download.maxmind.com` or `updates.maxmind.com`. Redirects are permitted only to the update hosts specified in the MaxMind documentation or to your designated R2 host. A `HEAD` request is used to check the `Last-Modified` header—this does not count toward your download quota. The actual download only proceeds if a new version is detected, at which point the `tar.gz.sha256` checksum is verified.

## Configuration and Execution

```sh
cd /var/lib
git clone git@github.com:shawngao-org/restricted-access.git
cd restricted-access
cp config.example.yaml /etc/restricted-access/config.yaml
openssl rand -base64 32
```

Enter the output into the `token.signing_key` field. Add your Account ID, License Key, and the country codes you wish to block to the same configuration file. Then, run:

```sh
mkdir /etc/restricted-access
chmod 640 /etc/restricted-access/config.yaml
go test ./...
make build
./bin/restricted-access check-config -config /etc/restricted-access/config.yaml
./bin/restricted-access update -config /etc/restricted-access/config.yaml
./bin/restricted-access serve -config /etc/restricted-access/config.yaml
```

The `check-config` command will not output your secret keys. Note that any relative `database_path` values are resolved based on the directory where the configuration file is located. 
When debugging locally without HTTPS, you must set both `gate.allow_insecure_http` to `true` and `token.cookie_secure` to `false`. 
Do not do this for production sites. `Secure` cookies cannot be issued over unencrypted HTTP.

## Nginx and systemd

```sh
cd /var/lib/restricted-access
cp deploy/restricted-access.conf /etc/nginx/conf.d/restricted-access.conf
# You must be change this config file content.
nginx -t && systemctl reload nginx
```

```sh
useradd --system --home /var/lib/restricted-access --shell /usr/sbin/nologin restricted-access
cd /var/lib/restricted-access
install -m 0755 bin/restricted-access /usr/local/bin/restricted-access
install -d -o root -g restricted-access -m 0750 /etc/restricted-access
install -m 0640 -o root -g restricted-access config.yaml /etc/restricted-access/config.yaml
install -m 0644 deploy/systemd/restricted-access.service /etc/systemd/system/restricted-access.service
systemctl daemon-reload
systemctl enable --now restricted-access
```

## Blacklist

`policy.deny_countries` uses two-letter country codes. By default, it checks the country of access, the country of registration, and the represented country. `policy.deny_subdivisions` uses a "Country-Subdivision" format (e.g., `US-CA`), where the subdivision code is derived from the selected GeoIP database. Since the "Country" database may not contain subdivision data, the "City" database should be used if subdivision-based filtering is required.

Requests from unknown addresses or private network addresses are denied by default. Access is also denied if the database is missing, the data type is incompatible, or the `max_stale` threshold is exceeded; the system will not permit access if it cannot definitively determine the origin.

## Startup Failure: "Failed at step USER"

Errors such as `Failed to determine user credentials: No such process` or `Failed at step USER spawning ...: No such process` occur during the user-switching phase in `systemd`, before the application itself has started. The "No such process" message indicates that `systemd` cannot locate the specified `User=` or `Group=`; it does *not* mean the executable file is missing.

First, inspect the active unit configuration, then verify that the account exists:

```sh
systemctl cat restricted-access.service
getent passwd restricted-access
getent group restricted-access
```

If `getent` produces no output, create the account before starting the service:

```sh
useradd --system --home /var/lib/restricted-access --shell /usr/sbin/nologin restricted-access
systemctl daemon-reload
systemctl restart restricted-access
```

Do not wrap the username in quotation marks (e.g., `User="restricted-access"` will trigger the same error). Once the account has been created, if the error changes to `No such file or directory` or `Permission denied`, check the `ExecStart` directive: it must point to the binary generated by `go build`, not to the `cmd/restricted-access` source code directory.
