Gem::Specification.new do |s|
  s.name = 'modsecurity_parsing'
  s.version = '0.1.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = "Recupération des types de tentatives d'attaques."
  s.description = "Basé sur le fonctionnement de https://github.com/bitsofinfo/logstash-modsecurity/"
  s.authors = ["William VINCENT"]
  s.email = 'contact@adminwiki.fr'
  s.homepage = "http://www.adminwiki.fr"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", ">= 2.0.0", "< 3.0.0"
  s.add_development_dependency 'logstash-devutils'
end
