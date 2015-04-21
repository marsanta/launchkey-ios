
Pod::Spec.new do |s|

  s.name         = "launchkey-ios"
  s.version      = "1.0.0"
  s.summary      = "LaunchKey iOS SDK"

  s.description  = "This iOS SDK enables developers to quickly integrate the LaunchKey platform and iOS based applications without the need to directly interact with the platform API."

  s.homepage     = "https://github.com/LaunchKey/launchkey-ios"

  s.license      = "MIT"

  s.author       = { "LaunchKey" => "support@launchkey.com" }

  s.platform     = :ios, "6.1"

  s.source       = { :git => "https://github.com/LaunchKey/launchkey-ios.git", :tag => "v1.0.0" }

  s.source_files =  'LaunchKeySDK.framework/Versions/A/Headers/*.h'
  s.vendored_frameworks = 'LaunchKeySDK.framework'
  
  s.frameworks = "CoreData", "UIKit", "Foundation", "Security"

  s.requires_arc = true

end
