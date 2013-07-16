# my_controller.rb

class MyController < Controller
  def start
    info "Hello Trema!"
    info "Controller started."
  end

  def packet_in dpid, message
    info "received a packet_in"
    info "dpid: #{dpid.to_hex}"
    info "in_port: #{message.in_port}"
    info "Source MAC: #{message.macsa}"
    info "Destination MAC: #{message.macda}"
    info "Ethernet type: #{message.eth_type}"
    info "TCP source port: #{message.tcp_src_port}"
    mask = 0xaa << 8
    if message.eth_type & mask == mask
      parse_log dpid, message
    end
  end

  def switch_ready dpid
    info "Switch connected: #{dpid.to_hex}"
  end

  def switch_disconnected dpid
    info "Switch disconnected: #{dpid.to_hex}"
  end

  private

  def parse_log dpid, message
    priority = message.eth_type & 0xff
    info "Priority: #{priority}"
    if priority == 14
      port_no = 2
    elsif priority == 15
      port_no = 3
    end
    send_flow_mod_add(
      dpid,
      :match => Match.new( :dl_type => message.eth_type),
      :actions => Trema::SendOutPort.new(port_no),
      :hard_timeout => 100
    )
    send_packet_out(
      dpid,
      :packet_in => message,
      :actions => Trema::SendOutPort.new(port_no)
    )
  end
end
