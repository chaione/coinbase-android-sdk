package com.coinbase.android.sdk;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;

import com.coinbase.api.Coinbase;
import com.coinbase.api.CoinbaseBuilder;
import com.coinbase.api.entity.OAuthCodeRequest;
import com.coinbase.api.entity.OAuthTokensResponse;
import com.coinbase.api.exception.CoinbaseException;
import com.coinbase.api.exception.UnauthorizedException;

import org.apache.http.client.utils.URIBuilder;
import org.joda.money.Money;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Random;

public class OAuth {

    private static final String KEY_COINBASE_PREFERENCES = "com.coinbase.android.sdk";
    private static final String KEY_LOGIN_CSRF_TOKEN = "com.coinbase.android.sdk.login_csrf_token";

    public static void beginAuthorization(Context context, String clientId,
                                          String scope, String redirectUri, OAuthCodeRequest.Meta meta)
            throws CoinbaseException {

        OAuthCodeRequest request = new OAuthCodeRequest();
        request.setClientId(clientId);
        request.setScope(scope);
        request.setRedirectUri(redirectUri);
        request.setMeta(meta);

        URI coinbaseAppUri = getCoinbaseAppUri(request);

        Intent intent = new Intent(Intent.ACTION_VIEW);
        Uri androidCoinbaseAppUri = Uri.parse(coinbaseAppUri.toString());
        androidCoinbaseAppUri = androidCoinbaseAppUri.buildUpon().appendQueryParameter("state", getLoginCSRFToken(context)).build();
        intent.setData(androidCoinbaseAppUri);

        PackageManager manager = context.getPackageManager();
        List<ResolveInfo> infos = manager.queryIntentActivities(intent, 0);

        if (infos.size() > 0) {
            // Coinbase app installed with support for access grants, open the app
            context.startActivity(intent);
        } else{
            // Coinbase app not installed, open the browser
            Coinbase coinbase = new CoinbaseBuilder().build();
            URI authorizationUri = coinbase.getAuthorizationUri(request);

            Intent i = new Intent(Intent.ACTION_VIEW);
            Uri androidUri = Uri.parse(authorizationUri.toString());
            androidUri = androidUri.buildUpon().appendQueryParameter("state", getLoginCSRFToken(context)).build();
            i.setData(androidUri);
            context.startActivity(i);
        }
    }

    public static OAuthTokensResponse completeAuthorization(Context context, String clientId,
                                                            String clientSecret, Uri redirectUri) throws UnauthorizedException, IOException {

        String csrfToken = redirectUri.getQueryParameter("state");
        String authCode = redirectUri.getQueryParameter("code");

        if (csrfToken == null || !csrfToken.equals(getLoginCSRFToken(context))) {
            throw new UnauthorizedException("CSRF Detected!");
        } else if (authCode == null) {
            String errorDescription = redirectUri.getQueryParameter("error_description");
            throw new UnauthorizedException(errorDescription);
        } else {
            try {
                Coinbase coinbase = new CoinbaseBuilder().build();
                Uri redirectUriWithoutQuery = redirectUri.buildUpon().clearQuery().build();
                return coinbase.getTokens(clientId, clientSecret, authCode, redirectUriWithoutQuery.toString());
            } catch (CoinbaseException ex) {
                throw new UnauthorizedException(ex.getMessage());
            }
        }
    }

    public static String getLoginCSRFToken(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(KEY_COINBASE_PREFERENCES, Context.MODE_PRIVATE);

        int result = prefs.getInt(KEY_LOGIN_CSRF_TOKEN, 0);
        if (result == 0) {
            result = (new Random()).nextInt();
            SharedPreferences.Editor e = prefs.edit();
            e.putInt(KEY_LOGIN_CSRF_TOKEN, result);
            e.commit();
        }

        return Integer.toString(result);
    }

    private static URI getCoinbaseAppUri(OAuthCodeRequest params) throws CoinbaseException {
        URIBuilder uriBuilder;
        try {
            uriBuilder = new URIBuilder("coinbase-oauth://oauth/authorize");
        } catch (URISyntaxException ex) {
            throw new AssertionError(ex);
        }
        uriBuilder.addParameter("response_type", "code");
        if (params.getClientId() != null) {
            uriBuilder.addParameter("client_id", params.getClientId());
        } else {
            throw new CoinbaseException("client_id is required");
        }
        if (params.getRedirectUri() != null) {
            uriBuilder.addParameter("redirect_uri", params.getRedirectUri());
        } else {
            throw new CoinbaseException("redirect_uri is required");
        }
        if (params.getScope() != null) {
            uriBuilder.addParameter("scope", params.getScope());
        } else {
            throw new CoinbaseException("scope is required");
        }
        if (params.getMeta() != null) {
            OAuthCodeRequest.Meta meta = params.getMeta();
            if (meta.getName() != null) {
                uriBuilder.addParameter("meta[name]", meta.getName());
            }
            if (meta.getSendLimitAmount() != null) {
                Money sendLimit = meta.getSendLimitAmount();
                uriBuilder.addParameter("meta[send_limit_amount]", sendLimit.getAmount().toPlainString());
                uriBuilder.addParameter("meta[send_limit_currency]", sendLimit.getCurrencyUnit().getCurrencyCode());
                if (meta.getSendLimitPeriod() != null) {
                    uriBuilder.addParameter("meta[send_limit_period]", meta.getSendLimitPeriod().toString());
                }
            }
        }
        try {
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new AssertionError(e);
        }
    }
}
