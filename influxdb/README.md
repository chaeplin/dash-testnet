'''
> influx
CREATE USER "username" WITH PASSWORD 'password' WITH ALL PRIVILEGES
CREATE DATABASE "databasename"
SHOW DATABASES
'''

influxdb.conf
```
[http]
  enabled = true
  bind-address = ":8086"
  auth-enabled = true
```

```
service influxdb restart
```

```
influx -username username -password '' -database databasename
password: 
Visit https://enterprise.influxdata.com to register for updates, InfluxDB server management, and monitoring.
Connected to http://localhost:8086 version 1.1.1
InfluxDB shell version: 1.1.1
>
```



