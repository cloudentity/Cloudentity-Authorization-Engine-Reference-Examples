package com.cloudentity.examples.trustengine;

import com.cloudentity.libs.trustengine.client.ApiClient;
import com.cloudentity.libs.trustengine.client.api.AuthzApi;
import com.cloudentity.libs.trustengine.client.model.ValidatorsData;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.cloudentity.examples.trustengine.config.Credentials.*;

public class AlwaysPassPolicyValidation {
  private static final ApiClient client = new ApiClient("oauth2_clientCredentials", clientId, clientSecret, null, null);
  private static AuthzApi authorizationServiceClient = client.buildClient(AuthzApi.class);

  private static Logger log = LoggerFactory.getLogger(AlwaysPassPolicyValidation.class);

  public static void main(String[] args) {
    try {
      log.info("Validating if policy passes");
      authorizationServiceClient.postAuthzApplicationPolicyWithPolicyNameValidate("ALWAYS_PASS", null, new ValidatorsData());
      log.info("Policy validated successfully");
    } catch (FeignException e) {
      log.warn("Request failed with status error: {}, message: {}", e.status(), e.getMessage());
    }
  }
}
