package org.dpppt.backend.sdk.model;

import javax.validation.constraints.NotNull;

public class OnSetRequest {
    @NotNull
    private String authorizationCode;
    @NotNull
    private Integer fake = 0;

    public OnSetRequest() {
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public Integer getFake() {
        return fake;
    }

    public void setFake(Integer fake) {
        this.fake = fake;
    }
}
