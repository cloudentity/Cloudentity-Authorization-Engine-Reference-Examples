package com.cloudentity.examples.trustengine;

import com.cloudentity.libs.trustengine.client.ApiClient;
import com.cloudentity.libs.trustengine.client.api.AuthzApi;
import com.cloudentity.libs.trustengine.client.model.ValidatorsData;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static com.cloudentity.examples.trustengine.config.Credentials.*;
import static com.cloudentity.examples.trustengine.helpers.Commons.basicABACWithPolicyName;

/**
 * this class shows how to validate ABAC policy against provided attributes
 *
 * Note: there is no user context in this example. Data for validation is provided in request body
 *
 * OLDER_THEN_38 should be a simple policy that checks if provided user age is grater then 38
 */
public class BasicABACPolicyValidation {

  private static Logger log = LoggerFactory.getLogger(BasicABACPolicyValidation.class);

  private static final ApiClient client = new ApiClient("oauth2_clientCredentials", clientId, clientSecret, null, null);
  private static AuthzApi authorizationServiceClient = client.buildClient(AuthzApi.class);

  private static final String validationAttributeFieldName = "attributes";
  private static Map<String, Object> mapWithAttributesSendForABACValidation = new HashMap<String, Object>() {
    {
      this.put("age", 43);
    }
  };

  public static void main(String[] args) {
    ValidatorsData validatorsData = new ValidatorsData();
    validatorsData.put(validationAttributeFieldName, mapWithAttributesSendForABACValidation);
    try {
      log.info("Validating if policy {} holds for attributes {}", basicABACWithPolicyName, validatorsData);
      authorizationServiceClient.postAuthzApplicationPolicyWithPolicyNameValidate(basicABACWithPolicyName, null, validatorsData);
      log.info("Policy validated successfully");
    } catch (FeignException e) {
      log.warn("Request failed with status error: {}, message: {}", e.status(), e.getMessage());
    }
  }
}
