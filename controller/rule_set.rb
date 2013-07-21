#!/usr/bin/ruby

require "flow_rule"
require "yaml"

class RuleSet
  def initialize(conf_file)
    @rules = []
    File.open(conf_file,"r") do |is|
      data = YAML.load(is)
      data.each do |h|
        key,value = h.shift
        @rules.push FlowRule.new key,value
      end
    end
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
end
