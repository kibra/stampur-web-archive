#!/bin/bash

yum install cmake
yum install libxml2-devel

SCRIPT=`readlink -f $0`
SCRIPTPATH=`dirname $SCRIPT`

adduser --system --no-create-home --disabled-login --disabled-password --group uwsgi
adduser --system --no-create-home --disabled-login --disabled-password --group nginx

cp ./init-scripts/nginx /etc/init.d/
chmod +x /etc/init.d/nginx
/usr/sbin/update-rc.d -f nginx defaults

cp ./init-scripts/uwsgi /etc/init.d/
chmod +x /etc/init.d/uwsgi
/usr/sbin/update-rc.d -f uwsgi defaults

cd /opt/
wget http://launchpad.net/libmemcached/1.0/1.0.2/+download/libmemcached-1.0.2.tar.gz
tar -zxvf libmemcached-1.0.2.tar.gz
cd libmemcached-1.0.2
./configure
make
make install

cd /opt/
wget http://fastdl.mongodb.org/linux/mongodb-linux-i686-2.0.2.tgz
tar -zxvf mongodb-linux-i686-2.0.2.tgz
cp mongodb-linux-i686-2.0.2/bin/* /usr/bin/

cd /opt/
wget http://projects.unbit.it/downloads/uwsgi-latest.tar.gz
tar -zxvf uwsgi-latest.tar.gz
rm uwsgi-latest.tar.gz
mv uwsgi-0.9.9.3 uwsgi/
cd uwsgi/
python setup.py install
chown -R uwsgi:uwsgi /opt/uwsgi
touch /var/log/uwsgi.log
chown uwsgi /var/log/uwsgi.log

cd /opt/
wget http://ctpp.havoc.ru/download/ctpp2-2.7.3.tar.gz
tar -zxvf ctpp2-2.7.3.tar.gz
rm ctpp2-2.7.3.tar.gz
cd ctpp2-2.7.3/
cmake .
make install

cd /opt/
wget http://dl.vbart.ru/ngx-ctpp/ngx_ctpp2-0.5.tar.gz
tar xzf ngx_ctpp2-0.5.tar.gz
wget http://nginx.org/download/nginx-1.1.11.tar.gz
tar -zxvf nginx-1.1.11.tar.gz
rm nginx-1.1.11.tar.gz
cd nginx-1.1.11/
./configure --prefix=/opt/nginx --user=nginx --group=nginx --add-module=../ngx_ctpp2-0.5 --with-cc-opt='-I ../ctpp2-2.7.3/build/include' --with-ld-opt="-L ../ctpp2-2.7.3/build/lib -Wl,-rpath,$PWD/../ctpp2-2.7.3/build/lib" 
make
make install

cd $SCRIPTPATH

cp ./nginx.conf /opt/nginx/nginx.conf

easy_install -U webob
easy_install -U pylibmc
easy_install -U mongoengine
easy_install -U Routes
easy_install -U bleach