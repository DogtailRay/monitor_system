require "rule_set"
require "yaml"

class ProcessClass
  attr_reader :rule_set
  def initialize(name, prerequisites, rules)
    @name = name
    @prerequisites = prerequisites
    @rule_set = RuleSet.new rules
  end

  def match?(prerequisites)
    @prerequisites == @prerequisites & prerequisites
  end
end

class ProcessSet
  @@required = ["prerequisites", "rules"]

  def initialize(conf_file)
    @conf_file = conf_file
    update
  end

  def update
    new_processes = []
    File.open(@conf_file, "r") do |is|
      data = YAML.load(is)
      data.each do |key,value|
        valid = true
        @@required.each do |field|
          unless value.has_key? field
            valid = false
            puts "Field \"#{field}\" missing for process: #{key}"
          end
        end
        new_processes.push ProcessClass.new(key, value["prerequisites"], value["rules"]) if valid
      end
    end
    @processes = new_processes
  end

  def find_process(prerequisites)
    @processes.each do |process|
      return process if process.match? prerequisites
    end
  end
end
