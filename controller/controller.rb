# log controller.rb

require "rule_set"
require "fdb"

class LogController < Controller

  DEFAULT_HARD_TIMEOUT = 50
  FACILITIES = %w/ kern user mail daemon auth syslog lpr news uucp cron auth ftp ntp audit alert cron /
  SEVERITIES = %w/ emerg alert crit error warn notice info debug /

  periodic_timer_event :query_stats, 10
  periodic_timer_event :age_fdbs, 30

  def start
    info "Log Controller started."
    @rule_set = RuleSet.new "rules.yaml"
    @switches = []
    # Create new FDB when accessing new dpid
    @fdbs = Hash.new do | hash, dpid |
      hash[ dpid ] = FDB.new
    end
  end

  def packet_in dpid, message
    fdb = @fdbs[ dpid ]
    fdb.learn message.macsa, message.in_port

    mask = 0xaa << 8
    if message.eth_type & mask == mask
      recv,port_no = parse_log message
      if recv
        port_no = fdb.port_no_of( recv )
      end
    else
      port_no = fdb.port_no_of( message.macda )
    end

    if port_no
      flow_mod_add dpid, message, port_no
      packet_out dpid, message, port_no
    else
      flood_out dpid, message
    end
  end

  def switch_ready dpid
    info "Switch connected: #{dpid.to_hex}"
    @switches << dpid
  end

  def switch_disconnected dpid
    info "Switch disconnected: #{dpid.to_hex}"
    @switches.delete dpid
  end

  def query_stats
    info "=================== Stats Report ==================="
    @switches.each do |dpid|
      send_message dpid, FlowStatsRequest.new(:match=>Match.new)
    end
  end

  def stats_reply dpid, message
    info "Switch #{dpid.to_hex}:"
    message.stats.each do |reply|
      info "#{reply.cookie.to_hex} duration: #{reply.duration_sec} packet count: #{reply.packet_count}"
    end
  end

  private

  def parse_log message
    # priority = facility << 3 + severity
    priority = message.eth_type & 0xff
    facility = FACILITIES[ priority / 8 ]
    severity = SEVERITIES[ priority % 8 ]
    rule = @rule_set.matching_rule( :eth_src => message.macsa,
                                    :eth_dst => message.macda,
                                    :facility => facility,
                                    :severity => severity )
    unless rule
      warn %Q/Can't find matching rule for
              src_mac:  #{message.macsa}
              src_dst:  #{message.macda}
              facility: #{facility}
              severity: #{severity}/
     rule = @rule_set.default_rule
    end
    [ rule.receiver, rule.out_port ]
  end


  def flow_mod_add dpid, message, port_no
    send_flow_mod_add(
      dpid,
      :match => Match.new( :dl_type => message.eth_type,
                           :dl_src => message.macsa,
                           :dl_dst => message.macda ),
      :actions => Trema::SendOutPort.new(port_no),
      :hard_timeout => DEFAULT_HARD_TIMEOUT
    )
  end

  def packet_out dpid, message, port_no
    send_packet_out(
      dpid,
      :packet_in => message,
      :actions => Trema::SendOutPort.new(port_no)
    )
  end

  def flood_out dpid, message
    packet_out dpid, message, OFPP_FLOOD
  end

  def age_fdbs
    @fdbs.each_value do | each |
      each.age
    end
  end
end
