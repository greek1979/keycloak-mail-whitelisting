package net.micedre.keycloak.registration;

import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.organization.OrganizationProvider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class RegistrationUserCreationWithMailDomainCheck extends RegistrationUserCreationDomainValidation {

   public static final String PROVIDER_ID = "registration-mail-check-action";

   private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

   public static String orgDomainCheckConfigName = "allowOrgDomains";
   public static String domainListConfigName = "validDomains";

   static {
      ProviderConfigProperty property;
      property = new ProviderConfigProperty();
      property.setName(orgDomainCheckConfigName);
      property.setLabel("Allow Organizations Domains");
      property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
      property.setHelpText("Allow domains of organizations of this realm.");
      CONFIG_PROPERTIES.add(property);
      property = new ProviderConfigProperty();
      property.setName(domainListConfigName);
      property.setLabel("Allowed Domains for E-mails");
      property.setType(ProviderConfigProperty.TEXT_TYPE);
      property.setHelpText("List mail domains authorized to register, separated by '##' or new line.");
      CONFIG_PROPERTIES.add(property);
   }

   @Override
   public String getDisplayType() {
      return "Profile Validation with E-mail Domain Check";
   }

   @Override
   public String getId() {
      return PROVIDER_ID;
   }

   @Override
   public String getHelpText() {
      return "Adds validation of domain emails for registration";
   }

   @Override
   public List<ProviderConfigProperty> getConfigProperties() {
      return CONFIG_PROPERTIES;
   }

   @Override
   public void buildPage(FormContext context, LoginFormsProvider form) {
      List<String> authorizedMailDomains = Arrays.asList(
         context.getAuthenticatorConfig().getConfig()
         .getOrDefault(domainListConfigName, DEFAULT_DOMAIN_LIST)
         .split(DOMAIN_LIST_SEPARATOR));
      form.setAttribute("authorizedMailDomains", authorizedMailDomains);
   }

   @Override
   public List<String> getDomainList(ValidationContext validationContext) {
      AuthenticatorConfigModel mailDomainConfig = validationContext.getAuthenticatorConfig();
      boolean orgDomains = Boolean.parseBoolean(mailDomainConfig.getConfig().get(orgDomainCheckConfigName));

      List<String> domainNames = new LinkedList<>();

      if (orgDomains && validationContext.getRealm().isOrganizationsEnabled()) {
    	     KeycloakSession session = validationContext.getSession();
         OrganizationProvider provider = session.getProvider(OrganizationProvider.class);
         provider.getAllStream()
            .flatMap(OrganizationModel::getDomains)
            .map(OrganizationDomainModel::getName)
            .collect(Collectors.toCollection(() -> domainNames));
      }

      domainNames.addAll(getDomainList(mailDomainConfig));

      return domainNames;
   }

   @Override
   public List<String> getDomainList(AuthenticatorConfigModel mailDomainConfig) {
      return List.of(mailDomainConfig.getConfig()
         .getOrDefault(domainListConfigName, DEFAULT_DOMAIN_LIST)
         .split(DOMAIN_LIST_SEPARATOR));
   }

   @Override
   public boolean isEmailValid(String email, List<String> domains) {
      for (String domain : domains) {
         if (email.endsWith("@" + domain) || email.equals(domain) || globmatches(email, "*@" + domain)) {
            return true;
         }
      }

      return false;
   }
}