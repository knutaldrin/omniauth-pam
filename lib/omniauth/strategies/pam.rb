module OmniAuth
  module Strategies
    class PAM
      include OmniAuth::Strategy

      option :name, 'pam'
      option :fields, [:username]
      option :uid_field, :username

      # this map is used to return gecos in info
      #option :gecos_map, [:name, :location, :phone, :home_phone, :description]
      # option :email_domain - if defined, info.email is build using uid@email_domain if not found from gecos
      # option :service - pam service name passed to rpam (/etc/pam.d/service_name), if not given rpam uses 'rpam'

      def request_phase
        OmniAuth::Form.build(
          :title => (options[:title] || "Authenticate"), 
          :url => callback_path
        ) do |field|
          field.text_field 'Username', 'username'
          field.password_field 'Password', 'password'
        end.to_response
      end

      def callback_phase
        #rpam_opts = Hash.new
        #rpam_opts[:service] = options[:service] unless options[:service].nil?

        unless Rpam.auth(request['username'], request['password'])
          return fail!(:invalid_credentials)
        end

        super
      end

      uid do
        request['username']
      end
      
      def primary_email
        return "#{uid}@stud.ntnu.no"
      end
      
      def email
        return primary_email
      end
      
      def emails
        return [primary_email]
      end
      
      def email_access_allowed?
        options['scope'] =~ /user/
      end

      info do
        info = { :nickname => uid, :name => uid, :email => primary_email }
      end
    end
  end
end

OmniAuth.config.add_camelization 'pam', 'PAM'
