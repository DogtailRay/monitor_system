#!/usr/bin/ruby

class FlowRule
  attr_reader :name,:out_port,:receiver
  @@field_list = ["@eth_src", "@eth_dst", "@facility", "@severity", "@pattern"]

  # [+:name+] Name of the rule
  # [+:eth_src+] Ethernet source address
  # [+:eth_dst+] Ethernet destination address
  # [+:facility+] Facility of the log
  # [+:severity+] Severity of the log
  # [+:pattern+] Pattern of the log content
  # [+:out_port+] Port to send out the package if the rule is matched
  # [+:receiver+] Mac address of log reciever
  def initialize(name,params)
    @name = name
    params.each do |attr,value|
      instance_variable_set "@#{attr}", value
    end
    @out_port ||= 1
  end

  # If the given parameters can match the rule
  # The rule is matched iff all none nil fields are matched
  # +params+ is a hash table of the following keys
  #   [+:eth_src+] Ethernet source address
  #   [+:eth_dst+] Ethernet destination address
  #   [+:facility+] Facility of the log
  #   [+:severity+] Severity of the log
  #   [+:content+] Content of the log, to be matched with the key words
  def match?(params)
    match = true
    instance_variables.each do |var|
      # if var is in the field list and it's value is not nil
      if @@field_list.include?(var) and val = instance_variable_get(var)
        match = match && params[var.gsub(/@/,'').to_sym].to_s =~ /#{val}/i
      end
    end
    match
  end

  def to_s
    "#{@name}"
  end
end

