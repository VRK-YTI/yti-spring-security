package fi.vm.yti.security.config;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;

public interface RestTemplateConfig {

    static HttpClient httpClient() {

        final TrustStrategy naivelyAcceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

        try {
            final SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(null, naivelyAcceptingTrustStrategy)
                .build();

            return HttpClients.custom()
                .setSSLSocketFactory(new SSLConnectionSocketFactory(sslContext))
                .build();

        } catch (final NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
