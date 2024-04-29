package com.test;

/*
https://github.com/bcgit/bc-java/blob/main/tls/src/test/java/org/bouncycastle/tls/test/MockPSKTlsServer.java#L21
 */

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.PSKTlsServer;

import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Strings;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.ChannelBinding;
import org.bouncycastle.util.encoders.Hex;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeOutputStream;
import java.security.SecureRandom;

import javax.xml.bind.DatatypeConverter;

public class MyPSKTlsServer extends PSKTlsServer {

	MyPSKTlsServer() {
		super(new BcTlsCrypto(new SecureRandom()), new MyIdentityManager());
	}

	protected Vector getProtocolNames() {
		Vector protocolNames = new Vector();
		protocolNames.addElement(ProtocolName.HTTP_2_TLS);
		protocolNames.addElement(ProtocolName.HTTP_1_1);
		return protocolNames;
	}

	public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
		PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
		out.println("TLS-PSK server raised alert: " + AlertLevel.getText(alertLevel)
				+ ", " + AlertDescription.getText(alertDescription));
		if (message != null) {
			out.println("> " + message);
		}
		if (cause != null) {
			cause.printStackTrace(out);
		}
	}

	public void notifyAlertReceived(short alertLevel, short alertDescription) {
		PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
		out.println("TLS-PSK server received alert: " + AlertLevel.getText(alertLevel)
				+ ", " + AlertDescription.getText(alertDescription));
	}

	public ProtocolVersion getServerVersion() throws IOException {
		ProtocolVersion serverVersion = super.getServerVersion();

		System.out.println("TLS-PSK server negotiated " + serverVersion);

		return serverVersion;
	}

	public void notifyHandshakeComplete() throws IOException {
		super.notifyHandshakeComplete();

		ProtocolName protocolName = context.getSecurityParametersConnection().getApplicationProtocol();
		if (protocolName != null) {
			System.out.println("Server ALPN: " + protocolName.getUtf8Decoding());
		}

		byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
		System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

		byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
		System.out.println("Server 'tls-unique': " + hex(tlsUnique));

		byte[] pskIdentity = context.getSecurityParametersConnection().getPSKIdentity();
		if (pskIdentity != null) {
			String name = Strings.fromUTF8ByteArray(pskIdentity);
			System.out.println("TLS-PSK server completed handshake for PSK identity: " + name);
		}
	}

	public void processClientExtensions(Hashtable clientExtensions) throws IOException {
		if (context.getSecurityParametersHandshake().getClientRandom() == null) {
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		super.processClientExtensions(clientExtensions);
	}

	public Hashtable getServerExtensions() throws IOException {
		if (context.getSecurityParametersHandshake().getServerRandom() == null) {
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		return super.getServerExtensions();
	}

	public void getServerExtensionsForConnection(Hashtable serverExtensions) throws IOException {
		if (context.getSecurityParametersHandshake().getServerRandom() == null) {
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		super.getServerExtensionsForConnection(serverExtensions);
	}

	protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
		// return
		// org.bouncycastle.tls.test.TlsTestUtils.loadEncryptionCredentials(context,
		// new String[] { "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" },
		// "x509-server-key-rsa-enc.pem");
		return null;
	}

	protected String hex(byte[] data) {
		return data == null ? "(null)" : Hex.toHexString(data);
	}

	protected ProtocolVersion[] getSupportedVersions() {
		// return ProtocolVersion.TLSv13.only();
		return ProtocolVersion.TLSv12.only();
	}

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		System.setProperty("jdk.tls.server.protocols", "TLSv1.2");
		try {
			InetAddress address = InetAddress.getLoopbackAddress();// .getLocalHost();
			int port = 8081;

			ServerSocket ss = new ServerSocket(port, 16, address);
			try {
				while (true) {
					Socket s = ss.accept();
					System.out.println(
							"--------------------------------------------------------------------------------");
					System.out.println("Accepted " + s);
					ServerThread t = new ServerThread(s);
					t.start();
				}
			} finally {
				ss.close();
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	static class ServerThread extends Thread {
		private final Socket s;

		ServerThread(Socket s) {
			this.s = s;
		}

		public void run() {
			try {
				MyPSKTlsServer server = new MyPSKTlsServer();
				TlsServerProtocol serverProtocol = new TlsServerProtocol(s.getInputStream(), s.getOutputStream());
				serverProtocol.accept(server);
				OutputStream log = new TeeOutputStream(serverProtocol.getOutputStream(), System.out);
				Streams.pipeAll(serverProtocol.getInputStream(), log);
				serverProtocol.close();
			} catch (Exception e) {
				throw new RuntimeException(e);
			} finally {
				try {
					s.close();
				} catch (IOException e) {
					System.out.println("Error " + e);
				}
			}
		}
	}

	static class MyIdentityManager
			implements TlsPSKIdentityManager {
		public byte[] getHint() {
			return Strings.toUTF8ByteArray("hint");
		}

		public byte[] getPSK(byte[] identity) {

			if (identity != null) {
				String name = Strings.fromUTF8ByteArray(identity);
				if (name.equals("client1")) {
					return  DatatypeConverter.parseHexBinary("b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d");
					//return hexStringToByteArray("b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d");
				}
			}
			return null;
		}
	}

	static byte[] hexStringToByteArray(String s) {
		byte[] data = new byte[s.length() / 2];
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) ((Character.digit(s.charAt(i * 2), 16) << 4)
					+ Character.digit(s.charAt(i * 2 + 1), 16));
		}
		return data;
	}
}
