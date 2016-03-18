# modsecurity_logstash_parsing
Recupération des types de tentatives d'attaques de ModSecurity pour ELK ( Elastic Search, LogStash, Kibana )

====================


### Installation rvm:
```
  curl -sSL https://get.rvm.io | bash -s stable
  rvm use jruby
  gem install jruby
  gem install logstash-devutils
  bundle install
```


### Installation Plugin
```
git clone https://github.com/willouuu/modsecurity_logstash_parsing.git
cd modsecurity_logstash_parsing/
gem build custom-modsec.gemspec
cd /opt/logstash/
bin/plugin install ~/modsecurity_logstash_parsing/custom_modsec-0.1.0.gem
bin/logstash -e 'input { stdin{} } filter { custom_modsec {} } output {stdout { codec => rubydebug }}'
```

### Configuration filebeat :
```
filebeat:
  prospectors:
    -
      paths:
        - /var/log/httpd/modsec_audit.log
      document_type: mod_security
      input_type: log
      fields:
         service: apache
         type: mod_security


  registry_file: /var/lib/filebeat/registry

output:
  logstash:
    hosts: ["xxx.xxx.xxx.xxx:5044"]
    bulk_max_size: 1024
    tls:
      certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
shipper:
logging:
  files:
```



### Configuration logstash :
```
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
filter {
  multiline {
    pattern => "^--[a-fA-F0-9]{8}-Z--$"
    negate => true
    what => previous
  }
  if [type] == "mod_security" {
    custom_modsec {}
  }
  if [type] == "mod_security" {
    mutate {
      remove_field => [ "message", "offset", "ResultH"]
    }
  }
}
output {
  stdout {
           codec => rubydebug
  }
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{type}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
```

### Lancement logstash debug
```
  /opt/logstash/bin/logstash -f /etc/logstash/conf.d/01-apache_modsec.conf -v --debug --verbose -w 1
  -w 1 : nombre de worker à 1 pour le multiline
```


### Index Kibana
Ajouter un index à kibana : mod_security-*


### Sources
Merci à bitsofinfo pour la partie extraction : https://github.com/bitsofinfo/logstash-modsecurity
