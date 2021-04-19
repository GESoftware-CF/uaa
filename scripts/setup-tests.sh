#!/bin/echo please source

unset_env() {
  unset HTTPS_PROXY
  unset HTTP_PROXY
  unset http_proxy
  unset https_proxy
  unset GRADLE_OPTS
  unset DEFAULT_JVM_OPTS
  unset JAVA_PROXY_OPTS
  unset PROXY_PORT
  unset PROXY_HOST
  env
}

set_chromedriver_proxy() {
  export http_proxy="http://10.229.23.245:3128"
  export https_proxy="http://10.229.23.245:3128"
  export HTTP_PROXY="http://10.229.23.245:3128"
  export HTTPS_PROXY="http://10.229.23.245:3128"
}
