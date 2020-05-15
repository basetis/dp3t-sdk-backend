package org.dpppt.backend.sdk.model;

public class OnSetResponse {
    private String accessToken;
    private String error;
    private Integer fake;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Integer getFake() {
        return fake;
    }

    public void setFake(Integer fake) {
        this.fake = fake;
    }
}
