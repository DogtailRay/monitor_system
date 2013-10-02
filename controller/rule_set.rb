#!/usr/bin/ruby

require "flow_rule"
require "yaml"

class RuleSet
  def initialize(rules)
    @rules = []
    rules.each do |key,value|
      @rules.push FlowRule.new key,value
    end
    @rules.sort! { |r1,r2| r1.name <=> r2.name }
    if rules.has_key? "default"
      new_default = FlowRule.new "default",data["default"]
    else
      new_default = @rules.first
    end
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
