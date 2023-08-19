# OVH Reconciler

Updates a DNS zone managed by OVH, using OVH API.

The source of truth is a plain-text file containing one DNS record per line.
If a difference is found between the contents of the file and the current
records, then the OVH API is queried to add or delete records until they match
what is defined in the file.

## Usage

```shell
./ovh_reconciler.py \
  --input=dns-zones.txt \
  --application_secret=186f21790a66a1c873efa4a1e7720c45c \
  --application_key=1b0c24317eba8cdb \
  --consumer_key=9f953cd64e5d32233192730ad1cdaaf1 \
  --dns_zone=myzone.fr
```

Where dns-zones.txt is a text file containing one record per line, for instance:

```
blog                          IN A      18.204.249.102
ng                            IN CNAME  nginx
ftp                           IN CNAME  @
ovh                           IN AAAA   2001:41d0:402:3300::1d20 
_dmarc                        IN TXT    ( "v=DMARC1; p=none" )
```

The application secret, application key and consumer key are issued by OVH
when [creating an API token](https://help.ovhcloud.com/csm/en-ca-api-getting-started-ovhcloud-api?id=kb_article_view&sysparm_article=KB0029722#create-your-app-keys).

This script requires the following permissions on `/domain/zone/myzone.fr`: GET
to fetch the current records and compare them with the intent, POST to create
new records and DELETE to remove records.

## Limitations

Only records of type A, AAAA, CNAME and TXT are supported. Other record types
are ignored.
