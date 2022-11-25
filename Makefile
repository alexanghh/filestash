all:
	make build_backend

build_init:
	find server/plugin/plg_* -type f -name "install.sh" -exec {} \;
	go generate -x ./server/...

build_frontend:
	NODE_ENV=production npm run build

build_backend:
	PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/ CGO_CFLAGS_ALLOW='-fopenmp' go build -mod=vendor --tags "fts5" -ldflags "-X github.com/mickael-kerjean/filestash/server/common.BUILD_DATE=`date -u +%Y%m%d` -X github.com/mickael-kerjean/filestash/server/common.BUILD_REF=`git rev-parse HEAD`" -o dist/filestash server/main.go

build_test:
	sed -i "s/plg_starter_http\"/plg_starter_https\"/g" server/plugin/index.go
	make build_frontend
	make build_backend

build_make_image:
	sed -i "s/plg_starter_https\"/plg_starter_http\"/g" server/plugin/index.go
	make build_frontend
	make build_backend
	docker pull machines/filestash
	docker pull ${USER}/filestash
	docker build -t ${USER}/filestash .

BUILD_DATE=$(shell date '+%Y%m%d-%H%M')
build_deploy_image:
	sed -i "s/plg_starter_https\"/plg_starter_http\"/g" server/plugin/index.go
	make build_frontend
	make build_backend
	$(info BUILD_DATE = $(BUILD_DATE))
	docker pull machines/filestash
	docker pull ${USER}/filestash
	docker build -t ${USER}/filestash .
	docker tag ${USER}/filestash ${USER}/filestash:$(BUILD_DATE)
	docker push ${USER}/filestash
	docker push ${USER}/filestash:$(BUILD_DATE)
	docker pull ${PRIVATE_DOCKER_REPO}/${USER}/filestash:$(BUILD_DATE)
