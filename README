### building

This allows for cross compiling to arm64 when using MacOS as a dev platform:

```bash
docker build -t pam-builder .                                                                                                                                                                  12s
docker create --name extract pam-builder
docker cp extract:/src/pam_jwt_pg.so ./pam_jwt_pg.so
docker rm extract
```

### setup on the server

Copy the `.so` to the server. And add to the correct pam location, normally:

```
/lib/aarch64-linux-gnu/security/
```

In the case of `nix` builds, such as the Supabase image, it needs to go the nix store:

```
cp pam_jwt_pg.so /nix/store/*-linux-pam-1.6.0/lib/security/
```

Next setup `/etc/pam.d/postgresql` with the following

```
auth required pam_jwt_pg.so jwks=https://auth.supabase.green/auth/v1/.well-known/jwks.json mappings=/tmp/users.yaml
account required pam_jwt_pg.so jwks=https://auth.supabase.green/auth/v1/.well-known/jwks.json mappings=/tmp/users.yaml
```

The `jwks` value should point to the URL of a valid .well-known/jwks.json end-point, that holds the keys used to sign JWTs
The `mappings` value shoudl be a file that contains the following:

```yaml
users:
  "user_email@supabase.io":
    roles:
      - supabase_read_only_user
      - some_other_role
```

This means that the user with the email claim `user_email@supabase.io` can login as either the `supabase_read_only_user` or `some_other_role`.

Finally setup the pg_hba.conf:

```
host  all  postgres  ::0/0     scram-sha-256
host all  all 0.0.0.0/0 pam
host all  all ::0/0 pam
```

Reload postgresql.service:

```
systemctl reload postgresql
```

And now login with JWT should work, as long as the JWT is signed by a key found in the jwks URL, the user email in the JWT matches one in the mappings file, the chosen postgres user role is permitted to the user and the JWT is still valid.
