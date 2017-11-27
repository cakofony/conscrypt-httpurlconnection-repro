package net.ckozak;

import com.google.common.io.ByteStreams;
import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.server.handlers.PathHandler;
import io.undertow.util.Headers;
import org.conscrypt.Conscrypt;
import org.junit.*;
import org.xnio.Options;
import org.xnio.Sequence;
import org.xnio.SslClientAuthMode;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class TestConscrypt {

    private static SSLContext conscryptContext;
    private static SSLContext sunJsseContext;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Provider conscryptProvider = Conscrypt.newProvider();
        Security.addProvider(conscryptProvider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream fis = new FileInputStream("server.keystore")) {
            ks.load(fis, "password".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "password".toCharArray());
        KeyManager[] keyManagers = kmf.getKeyManagers();

        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream fis = new FileInputStream("server.truststore")) {
            ts.load(fis, null);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] trustManagers = tmf.getTrustManagers();
        conscryptContext = SSLContext.getInstance("TLSv1.2", conscryptProvider.getName());
        conscryptContext.init(keyManagers, trustManagers, null);
        sunJsseContext = SSLContext.getInstance("TLSv1.2", "SunJSSE");
        sunJsseContext.init(keyManagers, trustManagers, null);
    }

    private static final int PORT = 8000;
    private Undertow server;

    @Before
    public void setUp() {
        // Simple webserver for testing.
        PathHandler handler = Handlers.path().addExactPath("/ping", exchange -> {
            exchange.setStatusCode(200);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
            exchange.getResponseSender().send("pong");
        });
        server = Undertow.builder()
                .addHttpsListener(PORT, null, sunJsseContext)
                .setHandler(handler)
                .setSocketOption(Options.SSL_CLIENT_AUTH_MODE, SslClientAuthMode.NOT_REQUESTED)
                .setSocketOption(Options.SSL_ENABLED_CIPHER_SUITES, Sequence.of(
                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
                .setSocketOption(Options.SSL_ENABLED_PROTOCOLS, Sequence.of("TLSv1.2"))
                .build();
        server.start();
    }

    @After
    public void tearDown() {
        server.stop();
    }

    @Test
    public void testDefault() {
        SSLSocketFactory socketFactory = conscryptContext.getSocketFactory();
        Conscrypt.setUseEngineSocket(socketFactory, false);
        Assert.assertEquals("pong", executeGetRequest("https://localhost:" + PORT + "/ping", socketFactory));
    }

    @Test
    public void testUseEngineSocket() {
        // Always takes exactly one minute, then returns the expected value!
        SSLSocketFactory socketFactory = conscryptContext.getSocketFactory();
        Conscrypt.setUseEngineSocket(socketFactory, true);
        Assert.assertEquals("pong", executeGetRequest("https://localhost:" + PORT + "/ping", socketFactory));
    }

    private static String executeGetRequest(String url, SSLSocketFactory socketFactory) {
        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
            connection.setSSLSocketFactory(socketFactory);
            connection.setHostnameVerifier((s, sslSession) -> true);
            try (InputStream response = connection.getInputStream()) {
                return new String(ByteStreams.toByteArray(response), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
