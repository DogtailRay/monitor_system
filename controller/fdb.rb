# This file is modified from fdb.rb in Trema example

class ForwardingEntry
  attr_reader :mac
  attr_reader :port_no
  attr_writer :age_max

  def initialize mac, port_no, age_max
    @mac = mac
    @port_no = port_no
    @age_max = age_max
    @last_update = Time.now
  end

  def update port_no
    @port_no = port_no
    @last_update = Time.now
  end

  def aged_out?
    aged_out = Time.now - @last_update > @age_max
    aged_out
  end
end

class FDB
  DEFAULT_AGE_MAX = 600

  def initialize
    @db = {}
  end

  def port_no_of mac
    dest = @db[ mac.to_s ]
    if dest
      dest.port_no
    else
      nil
    end
  end

  def learn mac, port_no
    mac = mac.to_s
    entry = @db[ mac ]
    if entry
      entry.update port_no
    else
      new_entry = ForwardingEntry.new mac, port_no, DEFAULT_AGE_MAX
      @db[ mac ] = new_entry
    end
  end

  def age
    @db.delete_if do | mac, entry |
      entry.aged_out?
    end
  end
end

