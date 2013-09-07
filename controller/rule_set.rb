#!/usr/bin/ruby

require "flow_rule"
require "yaml"

class RuleSet
  def initialize(conf_file)
    @conf_file = conf_file
    update
  end

  def update
    new_rules = []
    File.open(@conf_file,"r") do |is|
      data = YAML.load(is)
      data.each do |key,value|
        new_rules.push FlowRule.new key,value
      end
      new_rules.sort! { |r1,r2| r1.name <=> r2.name }
      if data.has_key? "default"
        new_default = FlowRule.new "default",data["default"]
      else
        new_default = new_rules.first
      end
    end
    @rules = new_rules
    @default = new_default
  end

  # Return the rule matching the given parameters
  def matching_rule(params)
    @rules.each do |rule|
      if rule.match? params
        return rule
      end
    end
    return nil
  end

  def default_rule
    @default
  end
end
