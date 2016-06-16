rm -fr build/ dist/ ovs.egg-info/
rm -fr build/bdist.linux-x86_64  build/lib.linux-x86_64-2.7 build/ovn  build/temp.linux-x86_64-2.7

python setup.py install
