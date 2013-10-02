#!/usr/bin/ruby

class FlowRule
  attr_reader :name,:out_port,:receiver
  @@field_list = ["eth_src", "mask", "type", "receiver", "out_port"]

  # [+:name+] Name of the rule
  # [+:eth_src+] Ethernet source address
  # [+:mask+]
  # [+:type+]
  # [+:out_port+] Port to send out the package if the rule is matched
  # [+:receiver+] Mac address of log reciever
  def initialize(name,params)
    @name = name
    params.each do |attr,value|
      if @@field_list.include? attr
        instance_variable_set "@#{attr}", value
      else
        puts "Unknown field \"#{attr}\" for rule \"#{name}\""
      end
    end
    @out_port ||= 1
  end

  # If the given parameters can match the rule
  # The rule is matched iff all none nil fields are matched
  # +params+ is a hash table of the following keys
  #   [+:eth_src+] Ethernet source address
  #   [+:type+]
  def match?(params)
    match = true
    if @eth_src
      match = match && params[:eth_src] =~ /#{@eth_src}/
    end
    type = params[:type]
    if @mask
      type = type & @mask
    end
    if @type
      match = match && type == @type
    end
    match
  end

  def to_s
    "#{@name}"
  end
end

