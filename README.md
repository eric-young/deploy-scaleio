# deploy-scaleio

This builds a ocker container that knows how to deploy a simple
ScaleIO deployment on three nodes. This configuration is not production ready but
can serve as a simple test bed

```
[user@host]$ docker build -t scaleio-deploy .

[user@host]$ docker run -it --rm scaleio-deploy
usage: deploy-scaleio.py [-h] [--ip [IP [IP ...]]]
                         [--username USERNAME]
                         [--password PASSWORD]
                         --package_url PACKAGE_URL
```