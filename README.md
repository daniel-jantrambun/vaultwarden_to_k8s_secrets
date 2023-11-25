# vaultwarden to k8s secret

The goal is to get items from vaultwarden and to install in kubernetes as secrets..

```bash
go install daniel-jantrambun/vaultwarden_to_k8s_secrets@latest
```

## QuickStart

Command

```bash
export PASSWORD='YOUR_PASSWORD'
export CLIENT_SECRET='YOUR_CLIENT_SECRET'
vaultwarden_to_k8s_secrets export -collection="k8s/<YOUR_NAMESPACE>/" -email="<YOU_EMAIL_ADDRESS>" -url="https://<YOUR_VAULT_URL>/api" -idturl "https://<YOUR_VAULT_URL>/identity"  -clientId="<YOU_CLIENT_ID>"
```

### Args

- collection : collection in vaultwarden. Collection's name must be formatted as `*_<namespace>`. The second element is the kubernetes `namespace``
- email: your email to connect to your vaultwarden
- url : you vaultwarden url
- clientId: your client id may be found in your profile in vaultwarden : Account/API Key/View API Key
- clientSecret (if not set in env or no arg, it will be asked): your client id may be found in your profile in vaultwarden : Account/API Key/View API Key
