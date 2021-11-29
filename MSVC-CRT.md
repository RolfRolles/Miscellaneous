In case you're reverse engineering a C++ program compiled with MSVC, and you can't match the binary to the headers on your machine, here is a list of repositories that contain various versions of the MSVC C/C++ CRT. I collected these by searching GitHub for `filename:crtversion.h _VC_CRT_BUILD_VERSION` and removing duplicates.

10.0.30319:  https://github.com/nihon-tc/Rtest/blob/8246e4d21323802fb84c406edc1a005991304f5a/header/Microsoft%20Visual%20Studio%2010.0/VC/include/

11.0.50522:  https://github.com/ir0nc0w/cross-compile_for_Windows/blob/08935f0864f497ee7fc6f13aba1b598701a04be1/VS2012/vc/include/
11.0.50727:  https://github.com/vovaboyko3007/SnakeGameRepository/blob/96af2ac69ebdf9ad0d5793b2efccb8e4c0fee1fb/Win32Project1/include/
11.0.51106:  https://github.com/TaurusTrade/TaurusTrade-platform-go/blob/06cc70d57b1539c2bdf00737fe0335dfa0acaf56/gateway-szkingdom-dll/vc_include/

12.0.30501:  https://github.com/ojdkbuild/tools_toolchain_vs2013e/blob/a6cea36c2e52a571864986ee2957fbd91d6f4ce8/VC/include/

14.0.23026:  https://github.com/dotfornet/VC-LTL/blob/50a8c414544585f836e552418a657df8b46113b8/VC140/
14.0.23419:  https://github.com/icestudent/vc-19-changes/blob/e9f49e36a28463963e8199ff7bc14222910598df/
14.0.23918:  https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.0.23918/include/
14.0.24210:  https://github.com/jackqk/MyStudy/blob/84313c1eaed7351d37b609288d1d32bf3b808859/DrvApp/StlInclude/
14.0.24218:  https://github.com/jjzhang166/vc-ltl/blob/4e9df5d0951b10b546290cd945a2ba31172b7a8e/VC/140/include/
14.0.24225:  https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.0.24225/include/
14.0.24231:  https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.0.24231/include/
14.0.24245:  https://github.com/suhao/toolchain/blob/ae4cb05c55ceceb7289bc28718ad22e2a8b6c474/vs2015/vc/include/
14.10.24728: https://github.com/light-tech/BuildSystem/blob/f847c745a6de199ac4108b96b20fba4783b07f60/include/msvc/
14.10.25017: https://github.com/jjzhang166/vc-ltl/blob/4e9df5d0951b10b546290cd945a2ba31172b7a8e/VC/141/include/
14.11.25506: https://github.com/omengxiang/cominc/blob/fa25bb947cddbd71bd11af864d3f2c1670487fe6/win/include/
14.12.25830: https://github.com/ojdkbuild/tools_toolchain_vs2017bt/blob/ee20a12c95b6a8b5942bf66a48424f61d560e938/VC/Tools/MSVC/14.12.25827/include/
14.13.26128: https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.13.26128/include/
14.14.26428: https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.14.26428/include/
14.15.26726: https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.15.26726/include/
14.16.27023: https://github.com/ir0nc0w/cross-compile_for_Windows/blob/08935f0864f497ee7fc6f13aba1b598701a04be1/VS2017/vc/include/
14.16.27033: https://github.com/ojdkbuild/tools_toolchain_vs2017bt_15936/blob/db988fa6fd0e2c972d816f1072e59e2cf1680126/VC/Tools/MSVC/14.16.27023/include/
14.20.27508: https://github.com/NoOne-hub/avc_save/blob/f216a197cd76dd639d509c4d89a88eead73d008c/MSVC_14.20.27508/
14.21.27702: https://github.com/0xCM/arrows/blob/b02c67b4f2a19518bec4c628c1516167eee934cc/asm/docs/headers/msvc/
14.22.27905: https://github.com/xe5700/JavaAppLauncher/blob/093def2c04acee96778fd4b21670f2e2e51fc1a9/VC-LTL/VC/14.22.27905/include/
14.23.28105: https://github.com/xe5700/JavaAppLauncher/blob/093def2c04acee96778fd4b21670f2e2e51fc1a9/VC-LTL/VC/14.23.28105/include/
14.24.28314: https://github.com/InsidersSoftware/SigmaSDK/blob/a83ed476e6169b317adef0068e1697a34a0ca9d3/Nuclear/
14.25.28610: https://github.com/Element-0/WINSDK/blob/eac8817e6283b510812fd8bffe41d486d9ae78b6/msvc/include/
14.26.28807: https://github.com/xe5700/JavaAppLauncher/blob/093def2c04acee96778fd4b21670f2e2e51fc1a9/VC-LTL/VC/14.26.28801/include/
14.27.29110: https://github.com/Chuyu-Team/VC-LTL/blob/489e2a9fe2b61ff73dfbcdf52052ec4da423f057/VC/14.27.29110/include/
14.28.29910: https://github.com/ngochungnguyenlg/SFML_game/blob/faf404611594198d57913753b47e55b95864db4c/SFML2.5/include/SFML/vs2019/
14.28.29912: https://github.com/Chuyu-Team/VC-LTL/blob/6e05e492773e14dc63fc73341f71e9e21b743ecf/VC/14.28.29910/include/
14.28.29333: https://github.com/AhyaZhilalikbar/TugasAkhir-GK-A_Kelompok-Kotak/blob/281a2079d2d9249599fcb105a589841df152c3d6/include/
14.29.30037: https://github.com/Chuyu-Team/VC-LTL/blob/b5f7e955bbbf133b225d72d1d45eeededdec504c/VC/14.29.30037/include/
14.29.30040: https://github.com/mulsicpp/CPPBuilder/blob/5bbd53ed697d8111e9d7e95273bad0f9f4f5171a/cppbuilder_win32/msvc/include/
14.29.30133: https://github.com/ojdkbuild/tools_toolchain_vs2019bt_16113/blob/8739e474753c93215ecade7c36bb0f96b7f3903b/VC/Tools/MSVC/14.29.30133/include/
