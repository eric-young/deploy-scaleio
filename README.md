# deploy-scaleio

This builds a docker container that knows how to deploy a simple
ScaleIO deployment on three nodes. This configuration is not production ready but
can serve as a simple test bed

It is assumed that each node has one device to add to the ScaleIO Pool, at /dev/sdb

```
[user@host]$ docker build -t scaleio-deploy .

[user@host]$ docker run -it --rm scaleio-deploy
usage: deploy-scaleio.py [-h] [--ip [IP [IP ...]]]
                         [--username USERNAME]
                         [--password PASSWORD]
                         --package_url PACKAGE_URL
```