# simple-ci
simple ci endpoint for use with webhooks

## Installation

1. Get the package
```bash
$ go get github.com/redmeros/simple-ci
```

2. Create new env file from template and update it to your specific needs
```bash
$ cd $GOPATH/src/github.com/redmeros/simple-ci/
$ cp .env.example .env
$ vim .env
```

3. Create scripts dir
```bash
$ mkdir -p /etc/simple-ci/scripts
```

4. Create scripts in `SCRIPTS_DIR` directory, each script should be executable, name of the script must be the same as repository name in github.

5. copy service to Systemd

```bash
$ sudo cp simple-ci.service /etc/systemd/system/
```

6. Reload systemd
```bash
sudo systemctl daemon-reload
```