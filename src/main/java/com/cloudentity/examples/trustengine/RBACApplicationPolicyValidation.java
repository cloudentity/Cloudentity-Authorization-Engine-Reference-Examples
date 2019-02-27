package com.cloudentity.examples.trustengine;

import com.cloudentity.libs.trustengine.client.ApiClient;
import com.cloudentity.libs.trustengine.client.api.AuthzApi;
import com.cloudentity.libs.trustengine.client.model.ValidatorsData;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static com.cloudentity.examples.trustengine.config.Credentials.clientId;
import static com.cloudentity.examples.trustengine.config.Credentials.clientSecret;
import static com.cloudentity.examples.trustengine.helpers.Commons.rbacPolicyName;
import static com.cloudentity.examples.trustengine.helpers.Commons.userUuid;

/**
 * this class shows how to validate RBAC policy without user context (RBAC is based on coarse grained permissions
 * and user id is taken from validation attributes)
 *
 * if run before PermissionManagement this example validation should fail
 * PermissionManagement should set proper permission so that below code should pass
 *
 */
public class RBACApplicationPolicyValidation {

  private static Logger log = LoggerFactory.getLogger(RBACApplicationPolicyValidation.class);

  private static final ApiClient client = new ApiClient("oauth2_clientCredentials", clientId, clientSecret, null, null);
  private static AuthzApi authorizationServiceClient = client.buildClient(AuthzApi.class);

  /**
   *  As in RBAC (which uses Coarse Grained Permission validator) access to parameters is done via 'attributes' key we need to create body
   *  with root object 'attributes' and put key 'userUuid' inside as visible on CAN_ACCESS_RBAC policy screenshot
   */
  private static final String validationAttributeFieldName = "attributes";
  private static Map<String, String> mapWithAttributesSendForPermissionValidation = new HashMap<String, String>() {
    {
      this.put("userUuid", userUuid);
    }
  };

  public static void main(String[] args) {
    ValidatorsData validationInput = new ValidatorsData();
    validationInput.put(validationAttributeFieldName, mapWithAttributesSendForPermissionValidation);
    try {
      log.info("Validating if policy {} holds for user", rbacPolicyName, userUuid);
      authorizationServiceClient.postAuthzApplicationPolicyWithPolicyNameValidate(rbacPolicyName, null, validationInput);
      log.info("Policy validated successfully");
    } catch (FeignException e) {
      log.warn("Request failed with status error: {}, message: {}", e.status(), e.getMessage());
    }
  }
}
