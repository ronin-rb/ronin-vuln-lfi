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

module Ronin
  module Vuln
    class LFI
      class File < StringIO

        # Path to the file
        attr_reader :path

        #
        # Creates a new Inclusion object.
        #
        # @param [String] path
        #   The path that was included.
        #
        # @param [String] body
        #   The body of the included file.
        #
        def initialize(path,body)
          super(body)

          @path = path
        end

        alias contents string
        alias to_s string

        def inspect
          "#<#{self.class}:#{@path}>"
        end

        #
        # Saves the body to a local file.
        #
        # @param [String] destination
        #   The destination path to save the file to.
        #
        # @return [String]
        #   The path of the saved file.
        #
        def save(destination)
          File.open(destination,'w') do |dest|
            dest.write(string)
          end

          return destination
        end

        def mirror(base)
          dest = File.join(base,@path)
          dest_dir = File.dirname(dest)

          unless File.directory?(dest_dir)
            FileUtils.mkdir_p(dest_dir)
          end

          return save(dest)
        end

      end
    end
  end
end