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

require 'ronin/vuln/lfi/signature'

module Ronin
  module Vuln
    class LFI
      Signature.log do |sig|
        sig.paths['Linux'] = ['/var/log/wtmp']

        sig.recognizor = /(tty\d+|:\d+)/
      end

      Signature.log do |sig|
        sig.paths['Linux'] = ['/var/log/apache/rewrite.log', '/var/log/apache2/rewrite.log']

        sig.recognizor = /init rewrite engine with requested uri/
      end

      Signature.log do |sig|
        sig.paths['Linux'] = ['/etc/syslog.conf']

        sig.recognizor = /kern\.(\*|emerg|alert|crit|err|warn(ing)?|notice|info|debug)/
      end
    end
  end
end
