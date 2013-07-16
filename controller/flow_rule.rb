#!/usr/bin/ruby

class FlowRule
  attr_reader :name,:eth_src,:eth_dst,:priority,:out_port
  @@ignore_list = ["@out_port", "@name"]

  def initialize(name,params)
    @name = name
    params.each do |attr,value|
      instance_variable_set "@#{attr}", value
    end
    @out_port ||= 1
  end

  def match?(params)
    match = true
    instance_variables.each do |var|
      if !ignore?(var) and val = instance_variable_get(var)
        match = match && val == params[var.gsub(/@/,'').to_sym]
      end
    end
    match
  end

  def ignore?(var)
    return @@ignore_list.include? var.to_s
  end
end

require "yaml"

rules = []
File.open("rules.yaml","r") do |is|
  data = YAML.load(is)
  data.each do |key,value|
    rules.push FlowRule.new key,value
  end
end

rules.each do |rule|
  puts rule.name
  puts rule.priority
end
