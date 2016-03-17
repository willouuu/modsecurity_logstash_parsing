# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# custom code to break up an event into multiple
class LogStash::Filters::Custom_modsec < LogStash::Filters::Base
  config_name "custom_modsec"
  #milestone 1


  config :message, :validate => :string, :default => "Default value"


  public
  def register
    # Nothing
  end # def register

  public
  def extractVal(pattern, fromString, storeResultIn, underKeyName, multiValues=false)
    if multiValues
      result = fromString.scan(pattern)
      if !result.empty?
        storeResultIn[underKeyName] = result.flatten
      end
    else
      result = pattern.match(fromString)
      if !result.nil?
        storeResultIn[underKeyName] = result[1]
      end
    end
  end




  public
  def filter(event)
    return unless filter?(event)
     begin

     if !event['message'].nil?

         modSecSectionData = event['message'].split(/(?:--[a-fA-F0-9]{8}-([A-Z])--)/)
         modSecSectionData.shift
         for i in 0..((modSecSectionData.length-1)/2)
             sectionName = 'rawSection'.concat(modSecSectionData.shift)
             sectionData = modSecSectionData.shift
             sectionName = sectionName.strip
             if !sectionData.nil?
                 sectionData = sectionData.strip
             if i==5
                  event.to_hash.merge!('ResultH' => sectionData)
             end
             end
         end

         if !event.to_hash['ResultH'].nil?
            trailer_array = event.to_hash['ResultH'].split(/\n/)
            trailer_array.each do |entry|
            if entry.match(/^Message: /)
               msg = Hash.new()
               extractVal(/Message: (.+)\s($|(\s*\[file))/, entry, msg, 'info')
               extractVal(/\[file \"(.*?)\"\]/, entry, msg, 'file')
               extractVal(/\[line \"(.*?)\"\]/, entry, msg, 'line')
               extractVal(/\[id \"(.*?)\"\]/, entry, msg, 'id')
               extractVal(/\[msg \"(.*?)\"\]/, entry, msg, 'msg')
               extractVal(/\[severity \"(.*?)\"\]/, entry, msg, 'severity')
               extractVal(/\[data \"(.*?)\"\]/, entry, msg, 'data')
               extractVal(/\[tag \"(.*?)\"\]/, entry, msg, 'tag')
               e =  LogStash::Event.new("@version" => "1",
                                        "@timestamp" => event["timestamp"],
                                        "info" => msg['info'],
                                        "file" => msg['file'],
                                        "line" => msg['line'],
                                        "id" => msg['id'],
                                        "msg" => msg['msg'],
                                        "severity" => msg['severity'],
                                        "data" => msg['data'],
                                        "tag" => msg['tag'],


                                        "input_type" => "log",
                                        "source" => "/var/log/httpd/modsec_audit.log",
                                        "type" => "mod_security"
                                       )
               yield e
               #event.cancel

            end
          end
     #filter_matched(event)
     end; end

     rescue Exception => e
         @logger.error("Ruby exception occurred: #{e}")
         event.tag("_rubyexception")
     end


  end
end
