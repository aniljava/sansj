package sansj;

import java.io.File;
import java.io.FilenameFilter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codehaus.jackson.map.ObjectMapper;

import com.google.common.net.InternetDomainName;

public class DNSServer {

	public static void main(String args[]) throws Exception {
		DNSServer server = new DNSServer();
		if (args.length >= 1) {
			server.configFolder = args[0];
		}

		if (args.length > 1) {
			server.reloadInterval = Integer.parseInt(args[1]);
		}

		if(args.length > 2){
			server.port = Integer.parseInt(args[2]);
		}
		
		
		server.execute();
	}

	public long		reloadInterval	= 5 * 60 * 1000;	// Every Five minutes
	public String	configFolder	= "config";
	public int		port			= 53;
	

	public void execute() throws Exception {
		loadDB();

		@SuppressWarnings("resource")
		final DatagramSocket serverSocket = new DatagramSocket(port);
		byte[] data = new byte[1024];

		
		long lastUpdated = System.currentTimeMillis();
		
		while (true) {
			
			if(lastUpdated + reloadInterval > System.currentTimeMillis()){
				loadDB();
			}

			DatagramPacket packet = new DatagramPacket(data, data.length);
			serverSocket.receive(packet);
			data = packet.getData();

			int length = packet.getLength();

			byte[] qname = new byte[length - 16];
			System.arraycopy(data, 12, qname, 0, length - 16);

			byte[] qtype = new byte[] { data[length - 4], data[length - 3] };
			byte[] qclass = new byte[] { data[length - 2], data[length - 1] };

			String query = qnameToDomain(qname);
			String type = getQType(qtype);
			String zone = getZone(query);

			ByteBuffer response = ByteBuffer.allocate(512);

			// Copy request id
			response.put((byte) data[0]);
			response.put((byte) data[1]);

			response.put((byte) ((1 << 7) | 4));// 10000100

			boolean error = false;
			switch (type) {
			case "a": {
				Map result = (Map) getData(zone, type);
				if (result == null) {
					error = true;
					break;
				}

				List<List<Object>> ARecords = (List<List<Object>>) result.get(query);
				if (ARecords == null || ARecords.isEmpty()) {
					// TODO CHECK CNAME BEFORE THROWING ERROR.
					error = true;
					break;
				}
				response.put((byte) 0); // NO ERROR
				response.putShort((short) 1); // QDCOUNT
				response.putShort((short) ARecords.size()); // ANCOUNT

				List<List> authority = (List<List>) getData(zone, "ns");
				if (authority != null && authority.size() > 0) {
					response.putShort((short) authority.size()); // NSCOUNT
				} else {
					response.putShort((short) 0); // NSCOUNT
				}
				response.putShort((short) 0); // ARCOUNT

				// Question Part
				response.put(qname);
				response.put(qtype);
				response.put(qclass);

				for (List<Object> record : ARecords) {
					// Pointer to answer part
					response.put((byte) 0xc0);
					response.put((byte) 0x0c);

					response.putShort((short) 1);// TYPE A
					response.putShort((short) 1);// CLASS IN

					int ttl = (int) record.get(0);
					String ip = (String) record.get(1);

					response.putInt(ttl);

					response.putShort((short) 4);

					byte[] address = Inet4Address.getByName(ip).getAddress();
					response.put(address);
				}

				if (authority != null && !authority.isEmpty()) {

					for (List auth : authority) {
						response.put(domainToQname(zone + "."));
						response.putShort((short) 2); // NS
						response.put(qclass); // IN

						int ttl = (int) auth.get(0);
						String cname = (String) auth.get(1);

						byte[] cnameQname = domainToQname(cname);

						response.putInt(ttl);
						response.putShort((short) (cnameQname.length)); // TODO

						response.put(cnameQname);
					}
				}

			}
				break;
			case "mx": {
				List<List<Object>> mxData = (List<List<Object>>) getData(zone, type);

				if (mxData == null || mxData.isEmpty()) {
					error = true;
					break;
				}

				response.put((byte) 0); // 0-000-0000 TODO replace last 0000
										// with error code.

				response.putShort((short) 1); // QDCOUNT
				response.putShort((short) mxData.size()); // ANCOUNT

				List<List> authority = (List<List>) getData(zone, "ns");
				if (authority != null && authority.size() > 0) {
					response.putShort((short) authority.size()); // NSCOUNT
				} else {
					response.putShort((short) 0); // NSCOUNT
				}

				response.putShort((short) 0); // ARCOUNT

				// NAME RECORD.
				response.put(qname);
				response.put(qtype);
				response.put(qclass);

				for (List<Object> record : mxData) {

					// NAME Pointer to above NAME RECORD
					response.put((byte) 0xc0);
					response.put((byte) 0x0c);

					response.putShort((short) 15);// TYPE MX
					response.putShort((short) 1); // CLASS IN

					int ttl = (int) record.get(0);
					int priority = (int) record.get(1);
					String cname = (String) record.get(2);

					byte[] cnameQname = domainToQname(cname);

					response.putInt(ttl);

					response.putShort((short) (cnameQname.length + 2)); // TODO

					// byte[] address = Inet4Address.getByName(ip).getAddress();
					response.putShort((short) priority);
					response.put(cnameQname);
				}

				if (authority != null && !authority.isEmpty()) {

					for (List auth : authority) {
						response.put(domainToQname(zone + "."));
						response.putShort((short) 2); // NS
						response.put(qclass); // IN

						int ttl = (int) auth.get(0);
						String cname = (String) auth.get(1);

						byte[] cnameQname = domainToQname(cname);

						response.putInt(ttl);
						response.putShort((short) (cnameQname.length)); // TODO

						response.put(cnameQname);
					}
				}

			}
				break;
			case "ns":
				response.put((byte) 3); // 0-000-0011 NAME ERROR
				break;
			case "txt":
				response.put((byte) 3); // 0-000-0011 NAME ERROR
				break;
			default:
				response.put((byte) 3); // 0-000-0011 NAME ERROR
				break;
			}

			if (error) {
				response.put((byte) 0); // 0-000-0011 NAME ERROR
				response.putShort((short) 1); // QDCOUNT
				response.putShort((short) 0); // ANCOUNT
				response.putShort((short) 0); // NSCOUNT
				response.putShort((short) 0); // ARCOUNT

				// NAME RECORD.
				response.put(qname);
				response.put(qtype);
				response.put(qclass);

			}
			DatagramPacket responsePacket = new DatagramPacket(response.array(), response.position(), packet.getAddress(), packet.getPort());
			serverSocket.send(responsePacket);
		}
	}

	public static byte[] domainToQname(String str) throws Exception {

		String[] strs = str.split("\\Q.\\E");

		ByteBuffer buffer = ByteBuffer.allocate(str.length() + 1);

		for (String part : strs) {
			buffer.put((byte) part.length());
			buffer.put(part.getBytes("ascii"));
		}
		buffer.put((byte) 0);

		return buffer.array();
	}

	public void loadDB() throws Exception {
		if (!new File(configFolder).exists()) {
			return;
		}

		File[] files = new File(configFolder).listFiles(new FilenameFilter() {

			@Override
			public boolean accept(File dir, String name) {
				return name.endsWith(".json");
			}
		});

		for (File file : files) {
			Map map = mapper.readValue(file, Map.class);
			String zone = map.get("zone").toString();
			db.put(zone, (Map<String, Object>) map.get("data"));
		}

	}

	private Map<String, Map<String, Object>>	db		= new HashMap<>();
	final ObjectMapper							mapper	= new ObjectMapper();

	private Object getData(String domain, String query) {

		Map<String, Object> map = db.get(domain);
		if (map == null) {
			return null;
		}
		return map.get(query);
	}

	public String getZone(String domainName) throws Exception {
		InternetDomainName domain = InternetDomainName.from(domainName);
		while (domain.hasParent()) {
			if (domain.parent().isPublicSuffix()) {
				break;
			}
			domain = domain.parent();
		}
		return domain.name();
	}

	private static String qnameToDomain(byte[] qname) {
		String result = null;
		boolean append = false;
		byte size = 0;
		for (byte b : qname) {
			if (b == 0) {
				break;
			}
			if (!append) {
				size = b;
				if (result != null) {
					result = result + ".";
				} else {
					result = "";
				}
				append = true;
			} else {
				result = result + Character.toLowerCase((char) b);
				size--;
			}

			if (size == 0) {
				append = false;
			}
		}

		return result;
	}

	private static String getQType(byte b[]) {

		int i = 0;
		i |= b[0] & 0xFF;
		i <<= 8;
		i |= b[1] & 0xFF;

		String qtype;

		switch (i) {
		case 1:
			qtype = "a"; // a host address
			break;
		case 2:
			qtype = "ns"; // an authoritative name server
			break;
		case 6:
			qtype = "soa"; // marks the start of a zone of authority
			break;
		case 15:
			qtype = "mx"; // mail exchange
			break;
		case 16:
			qtype = "txt"; // text strings
			break;
		default:
			return "NOT IMPLEMENTED";
		}

		return qtype;
	}
}
