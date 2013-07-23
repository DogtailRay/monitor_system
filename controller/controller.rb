# log controller.rb

require "rule_set"

class LogController < Controller
  periodic_timer_event :query_stats, 10

  def start
    info "Log Controller started."
    @rule_set = RuleSet.new "rules.yaml"
    @switches = []
  end

  def packet_in dpid, message
    mask = 0xaa << 8
    if message.eth_type & mask == mask
      parse_log dpid, message
    else
      info "received a packet_in"
      info "dpid: #{dpid.to_hex}"
      info "Ethernet type: #{message.eth_type}"
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
    @switches.each do |dpid|
      send_message dpid, FlowStatsRequest.new(:match=>Match.new)
    end
  end

  def stats_reply dpid, message
    info "Switch #{dpid.to_hex}:"
    message.stats.each do |reply|
      info reply.to_s
    end
  end

  private

  def parse_log dpid, message
    rule = matching_rule(message)
    content = message.data[40..-1]
    puts "Content: #{content}"
    if rule
      port_no = rule.out_port
      send_flow_mod_add(
        dpid,
        :match => Match.new( :dl_type => message.eth_type,
                             :dl_src => message.macsa,
                             :dl_dst => message.macda ),
        :actions => Trema::SendOutPort.new(port_no),
        :hard_timeout => 20
      )
      send_packet_out(
        dpid,
        :packet_in => message,
        :actions => Trema::SendOutPort.new(port_no)
      )
    end
  end

  def matching_rule message
    priority = message.eth_type & 0xff
    @rule_set.matching_rule( :eth_src => message.macsa,
                             :eth_dst => message.macda,
                             :priority => priority )
  end
end
