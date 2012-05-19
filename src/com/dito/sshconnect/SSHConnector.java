package com.dito.sshconnect;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.channels.Channels;
import java.nio.channels.Pipe;
import java.security.SecureRandom;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.mindbright.nio.NetworkConnection;
import com.mindbright.nio.NonBlockingOutput;
import com.mindbright.ssh2.SSH2ConsoleRemote;
import com.mindbright.ssh2.SSH2FTPProxyFilter;
import com.mindbright.ssh2.SSH2SimpleClient;
import com.mindbright.ssh2.SSH2StreamFilterFactory;
import com.mindbright.ssh2.SSH2StreamSniffer;
import com.mindbright.ssh2.SSH2Transport;
import com.mindbright.util.RandomSeed;
import com.mindbright.util.SecureRandomAndPad;
import com.mindbright.util.Util;

public class SSHConnector {

	private static Options options = null; // Command line options

	private static final String COMMAND_LINE_OPTION = "cl";

	private static final String PROPERTY_FILE_OPTION = "pr";
	private static final String DEFAULT_PROPERTY_FILE = "ssh.properties";

	private static CommandLine cmd = null; // Command Line arguments

	private static String propsFile = DEFAULT_PROPERTY_FILE;
	static {
		options = new Options();

		options.addOption(COMMAND_LINE_OPTION, true, "Command line string");

		options.addOption(PROPERTY_FILE_OPTION, true, "Property file ("
				+ DEFAULT_PROPERTY_FILE + " by default)");

	}
	private Properties props;
	private String host;
	private String passwd;
	private int port;
	private String user;
	private SSH2SimpleClient client;

	private static String loadArgs(String[] args) {

		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("SSHConnector", options);
		CommandLineParser parser = new PosixParser();
		String result = null;
		try {

			cmd = parser.parse(options, args);

		} catch (ParseException e) {

			System.err.println("Error parsing arguments");

			e.printStackTrace();

			System.exit(1);

		}

		if (cmd.hasOption(COMMAND_LINE_OPTION)) {
			result = cmd.getOptionValue(COMMAND_LINE_OPTION);
		}

		if (cmd.hasOption(PROPERTY_FILE_OPTION)) {
			propsFile = cmd.getOptionValue(PROPERTY_FILE_OPTION);

		}
		System.out.println("propsFile=" + propsFile);
		return result;
	}

	public static void main(String[] argv) throws Exception {

		Properties props = new Properties();
		String command = loadArgs(argv);
		try {
			props.load(new FileInputStream(propsFile));
		} catch (Exception e) {
			System.out.println("Error loading properties: " + e.getMessage());
		}
		;
		SSHConnector ssh2 = new SSHConnector(props);
		ssh2.connect(command);

	}

	public SSHConnector(Properties props) {
		this.props = props;
	}

	private static int getPort(String port) {
		int p;
		try {
			p = Integer.parseInt(port);
		} catch (Exception e) {
			p = 22;
		}
		return p;
	}

	public void connect(String command) throws Exception {
		host = props.getProperty("server");
		port = getPort(props.getProperty("port"));
		user = props.getProperty("username");
		port = Util.getPort(host, port);
		host = Util.getHost(host);
		passwd = props.getProperty("password");
		NetworkConnection socket = NetworkConnection.open(host, port);
		SSH2Transport transport = new SSH2Transport(socket,
				createSecureRandom());
		client = new SSH2SimpleClient(transport, user, passwd);

		boolean commandNotExists = command == null
				|| command.trim().length() == 0;
		String cmdLine = commandNotExists ? "ping localhost -t" : command;
		if (commandNotExists)
			startForwards();
		else {
			System.out.println("Starting executing command:" + cmdLine);
		}
		SSH2ConsoleRemote console = new SSH2ConsoleRemote(
				client.getConnection());

		int exitStatus = -1;

		/*
		 * Run the command. Here we redirect stdout and stderr of the remote
		 * command execution to a file named "out" for simplicity.
		 */
		Pipe pipe = Pipe.open();
		NonBlockingOutput out = new NonBlockingOutput(pipe);

		if (console.command(cmdLine, null, out, out)) {
			/*
			 * Fetch the internal stdout stream and wrap it in a BufferedReader
			 * for convenience.
			 */
			BufferedReader stdout = new BufferedReader(new InputStreamReader(
					Channels.newInputStream(pipe.source())));

			/*
			 * Read all output sent to stdout (line by line) and print it to our
			 * own stdout.
			 */
			String line;
			while ((line = stdout.readLine()) != null) {
				if (!commandNotExists)
					System.out.println(line);
			}

			/*
			 * Retrieve the exit status of the command (from the remote end).
			 */
			exitStatus = console.waitForExitStatus();
		} else {
			System.err.println("failed to execute command: " + cmdLine);
		}

		/*
		 * NOTE: at this point System.out will be closed together with the
		 * session channel of the console
		 */

		/*
		 * Disconnect the transport layer gracefully
		 */
		transport.normalDisconnect("User disconnects");

		/*
		 * Exit with same status as remote command did
		 */
		System.exit(exitStatus);

	}

	/**
	 * Parses a port forward spec of the following format:
	 * <code>/plugin/local_host:local_port:remote_host:remote_port</code> Where
	 * <code>/plugin/</code> and <code>local_host:</code> are optional.
	 * <p>
	 * local_host and remote_host may be names or literal IPv4 addreses. They
	 * can also be literal IPv6 addresses enclosed in (<code>[]</code>).
	 * 
	 * @param spec
	 *            the port forward spec
	 * @param local
	 *            defaukt local listenber address
	 * @return an array of five objects
	 */
	public static Object[] parseForwardSpec(String spec, Object local)
			throws IllegalArgumentException {
		int d1, d2, d3;
		String tmp = spec;
		Object[] components = new Object[5];

		// Plugin
		if (tmp.startsWith("/")) {
			int i = tmp.indexOf('/', 1);
			if (i == -1) {
				throw new IllegalArgumentException(
						"Invalid port forward spec. " + spec);
			}
			components[0] = tmp.substring(1, i);
			tmp = tmp.substring(i + 1);
		} else {
			components[0] = "general";
		}

		// local_host
		if (tmp.startsWith("[") && -1 != (d1 = tmp.indexOf(']', 1))
				&& ':' == tmp.charAt(d1 + 1)) {
			components[1] = tmp.substring(1, d1);
			tmp = tmp.substring(d1 + 2); // ]:

		} else if (-1 != (d1 = tmp.indexOf('['))
				&& -1 != (d2 = tmp.indexOf(':'))
				&& -1 != (d3 = tmp.indexOf(':', d2 + 1)) && d2 < d1 && d3 < d1) {
			components[1] = tmp.substring(0, d1);
			tmp = tmp.substring(d1 + 1);

		} else if (-1 == tmp.indexOf('[') && -1 != (d1 = tmp.indexOf(':'))
				&& -1 != (d2 = tmp.indexOf(':', d1 + 1))
				&& -1 != tmp.indexOf(':', d2 + 1)) {
			components[1] = tmp.substring(0, d1);
			tmp = tmp.substring(d1 + 1);
		} else {
			components[1] = local;
		}

		// local_port
		if (0 == (d1 = tmp.indexOf(':'))) {
			throw new IllegalArgumentException("Invalid port forward spec. "
					+ spec);
		}
		components[2] = Integer.valueOf(tmp.substring(0, d1));
		tmp = tmp.substring(d1 + 1);

		// remote_host
		if (tmp.startsWith("[") && -1 != (d1 = tmp.indexOf(']', 1))
				&& ':' == tmp.charAt(d1 + 1)) {
			components[3] = tmp.substring(1, d1);
			tmp = tmp.substring(d1 + 2);
		} else if (-1 != (d1 = tmp.indexOf(':'))) {
			components[3] = tmp.substring(0, d1);
			tmp = tmp.substring(d1 + 1);
		} else {
			// throw new IllegalArgumentException("Invalid port forward spec. "
			// +
			// spec);
			components[3] = tmp;
			tmp = components[2] + "";
		}

		// remote_port
		components[4] = Integer.valueOf(tmp);

		return components;
	}

	/**
	 * Starts any portforwards specified in the properties.
	 */
	private void startForwards() {
		int i;
		for (i = 0; i < 32; i++) {
			String spec = props.getProperty("local" + i);
			if (spec == null)
				break;
			Object[] components = parseForwardSpec(spec, "0.0.0.0");
			try {
				SSH2StreamFilterFactory filter = null;
				if ("ftp".equals(components[0])) {
					filter = new SSH2FTPProxyFilter((String) components[1],
							host);
				} else if ("sniff".equals(components[0])) {
					filter = SSH2StreamSniffer.getFilterFactory();
				}
				client.getConnection().newLocalForward((String) components[1],
						((Integer) components[2]).intValue(),
						(String) components[3],
						((Integer) components[4]).intValue(), filter);
				System.out.println("started local forward: " + spec);
			} catch (IOException e) {
				System.out.println("failed local forward: " + spec
						+ e.getMessage());
			}
		}
		for (i = 0; i < 32; i++) {
			String spec = props.getProperty("remote" + i);
			if (spec == null)
				break;
			Object[] components = parseForwardSpec(spec, "0.0.0.0");
			client.getConnection().newRemoteForward((String) components[1],
					((Integer) components[2]).intValue(),
					(String) components[3],
					((Integer) components[4]).intValue());
			System.out.println("started remote forward: " + spec);
		}
	}

	/**
	 * Create a random number generator. This implementation uses the system
	 * random device if available to generate good random numbers. Otherwise it
	 * falls back to some low-entropy garbage.
	 */
	private static SecureRandomAndPad createSecureRandom() {
		byte[] seed;
		File devRandom = new File("/dev/urandom");
		if (devRandom.exists()) {
			RandomSeed rs = new RandomSeed("/dev/urandom", "/dev/urandom");
			seed = rs.getBytesBlocking(20);
		} else {
			seed = RandomSeed.getSystemStateHash();
		}
		return new SecureRandomAndPad(new SecureRandom(seed));
	}
}
