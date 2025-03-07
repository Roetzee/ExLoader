#include <windows.h>
#include <windowsx.h>

#include <stdio.h>
#include <fstream>

#include <string>
#include "KeyAuth.hpp"

#include <d3d9.h>
#include <d3dx9.h>
#include <ob.h>
#include "montserrat.h"

#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_dx9.h"
#include "ImGui/imgui_impl_win32.h"
#include <iostream>
#include <ostream>

#pragma warning(push, 0)
#include "libs\curl\include\curl\curl.h"
#pragma warning(pop)

#include "Inject.h"

#include "MD5/MD5.h"
#include "XorComp.hpp"
#include "lazy.hpp"
#include <xorstr.hpp>
#include "Antidebug.h"
#include <filesystem>

#include "Verdana.h"
#include "protect.h"
#include "skStr.h"

using std::string;
using namespace std;
using std::ifstream;
IDirect3DDevice9* g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS g_d3dpp;
IDirect3D9* pD3D = nullptr;

ImVec2 pos = { 0, 0 };

using namespace KeyAuth;

auto name = skCrypt("Expensive"); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
auto ownerid = skCrypt("kEyJeMug3Y"); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
auto secret = skCrypt("9d5fcc558000ed495b6dc5f1819a114b1782f5e33a16b8a3c2007cdf4e480a63"); // app secret, the blurred text on licenses tab and other tabs
auto version = skCrypt("1.0"); // leave alone unless you've changed version on website
api KeyAuthApp(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt());

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, message, wParam, lParam))
		return true;

	switch (message) {
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			ImGui_ImplDX9_InvalidateDeviceObjects();
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
			if (hr == D3DERR_INVALIDCALL) IM_ASSERT(0);
			ImGui_ImplDX9_CreateDeviceObjects();
		}
		return 0;

	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
		break;
	case WM_DESTROY:
		LI_FN(PostQuitMessage)(0);
		return 0;
	}

	return LI_FN(DefWindowProcA).cached()(hWnd, message, wParam, lParam);
}

int writer(char* data, size_t size, size_t nmemb, string* buffer)
{
	int result = 0;
	if (buffer != NULL)
	{
		buffer->append(data, size * nmemb);
		result = size * nmemb;
	}
	return result;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

__forceinline string GetHwid()
{
	DWORD dwVolumeSerialNumber;
	string ret;
	if (LI_FN(GetVolumeInformationA)(_("C:\\"), nullptr, 0, &dwVolumeSerialNumber, nullptr, nullptr, nullptr, 0))
		ret = md5(md5(std::to_string((dwVolumeSerialNumber << 3) - 4)));
	else
		ret = string();

	return ret;
}

size_t write_data(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

__forceinline void RemoveFile(string file)
{
	LI_FN(SetFileAttributesA)(file.c_str(), FILE_ATTRIBUTE_NORMAL);
	LI_FN(DeleteFileA)(file.c_str());
}

void TextCentered(std::string text) {
	auto windowWidth = ImGui::GetWindowSize().x;
	auto textWidth = ImGui::CalcTextSize(text.c_str()).x;

	ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
	ImGui::Text(text.c_str());
}

void TextCenteredGenesis(std::string text) {
	auto windowWidth = 390;
	auto textWidth = ImGui::CalcTextSize(text.c_str()).x;

	ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
	ImGui::Text(text.c_str());
}

BOOL WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
	JUNK_CODE_ONE
	LI_FN(CreateThread)(nullptr, 0, Thread, nullptr, 0, nullptr);

	KeyAuthApp.init();
	if (std::filesystem::exists("C:\\Windows\\Logs\\DirectX\\render.log"))
		std::filesystem::remove("C:\\Windows\\Logs\\DirectX\\render.log");

	
		JUNK_CODE_ONE
			if (IsAdministrator() == FALSE)
			{
				MessageBox(NULL, "Open Loader As Administrator", "Expensive", MB_OK);
				exit(1);
			}

		string currentversion = "1.0";  // change to update version

				AntiDump();
				HideFromDebugger();
				DebugChecker();
				AntiAttach();

				LI_FN(LoadLibraryA)(_("d3d9.dll"));
				LI_FN(LoadLibraryA)(_("d3dx9_43.dll"));
				LI_FN(LoadLibraryA)(_("XINPUT1_3.dll"));
				LI_FN(LoadLibraryA)(_("ntdll.dll"));

				RECT rect;
				LI_FN(GetWindowRect)(LI_FN(GetDesktopWindow)(), &rect);
				pos.x = rect.right / 2 - 200;
				pos.y = rect.bottom / 2 - 200;

				int phase = 0;
				int print = 0;
				int dababy = 0;
				static char key[64] = { 0 };
				bool hovered = false;
				POINT lpx;
				LPDIRECT3DTEXTURE9 logo = 0;
				MSG msg;
				HWND hwnd = 0;

				WNDCLASSEX wc;
				ZeroMemory(&wc, sizeof(WNDCLASSEX));

				wc.cbSize = sizeof(WNDCLASSEX);
				wc.hInstance = hInst;
				wc.lpfnWndProc = WndProc;
				wc.lpszClassName = _("Expensive");
				wc.style = CS_HREDRAW | CS_VREDRAW;

				if (!LI_FN(RegisterClassExA)(&wc))
				{
					LI_FN(MessageBoxA)(nullptr, _("Failed to open window"), _("Expensive"), 0);
					return 1;
				}

				hwnd = LI_FN(CreateWindowExA)(0, wc.lpszClassName, _("Expensive"), WS_POPUP, 10, 10, 400, 400, nullptr, nullptr, wc.hInstance, nullptr);
				if (!hwnd)
				{
					LI_FN(UnregisterClassA)(wc.lpszClassName, wc.hInstance);
					LI_FN(MessageBoxA)(nullptr, _("Failed to open window"), _("Expensive"), 0);
					return 1;
				}

				pD3D = LI_FN(Direct3DCreate9)(D3D_SDK_VERSION);
				if (!pD3D)
				{
					LI_FN(UnregisterClassA)(wc.lpszClassName, wc.hInstance);
					LI_FN(MessageBoxA)(nullptr, _("Failed to initialize DirectX"), _("Expensive"), 0);
					return 1;
				}

				string namaste = xorstr_("vw3n69secwytf");

				ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
				g_d3dpp.Windowed = TRUE;
				g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
				g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
				g_d3dpp.EnableAutoDepthStencil = TRUE;
				g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
				g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
				JUNK_CODE_ONE

					if (pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
					{
						pD3D->Release();
						LI_FN(UnregisterClassA)(wc.lpszClassName, wc.hInstance);
						return 1;
					}

				ImGui::CreateContext();

				ImGuiIO& io = ImGui::GetIO(); (void)io;
				io.Fonts->AddFontFromMemoryCompressedTTF(verdana_compressed_data, verdana_compressed_size, 15.0f);
				ImFont* montserrat1 = io.Fonts->AddFontFromMemoryTTF((void*)montserrat, sizeof(montserrat), 50.0f);

				ImGui_ImplWin32_Init(hwnd);
				ImGui_ImplDX9_Init(g_pd3dDevice);
				JUNK_CODE_ONE
					LI_FN(ShowWindow)(hwnd, SW_SHOW);
				LI_FN(UpdateWindow)(hwnd);
				{
					auto& style = ImGui::GetStyle();
					style.FramePadding = { 8, 4 };
					style.ScrollbarSize = 14;
					style.GrabMinSize = 8;
					style.WindowBorderSize = 0.5f;
					style.PopupBorderSize = 0;
					style.FrameBorderSize = 0;
					style.WindowRounding = 0;
					style.FrameRounding = 0;
					style.PopupRounding = 0;
					style.ScrollbarRounding = 9;
					style.GrabRounding = 12;
					style.TabRounding = 4;

					auto colors = style.Colors;
					colors[ImGuiCol_Text] = ImColor(255, 255, 255, 200);
					colors[ImGuiCol_WindowBg] = ImColor(20, 20, 20);
					colors[ImGuiCol_ChildBg] = ImColor(60, 60, 60);
					colors[ImGuiCol_PopupBg] = ImColor(30, 30, 30);
					colors[ImGuiCol_FrameBg] = ImColor(25, 25, 25);
					colors[ImGuiCol_FrameBgHovered] = ImColor(130, 132, 170, 200);
					colors[ImGuiCol_FrameBgActive] = ImColor(130, 132, 170);
					colors[ImGuiCol_ScrollbarBg] = ImColor();
					colors[ImGuiCol_ScrollbarGrab] = ImColor(130, 132, 170, 150);
					colors[ImGuiCol_ScrollbarGrabHovered] = ImColor(130, 132, 170, 200);
					colors[ImGuiCol_ScrollbarGrabActive] = ImColor(130, 132, 170);
					colors[ImGuiCol_SliderGrab] = ImColor(130, 132, 170, 200);
					colors[ImGuiCol_SliderGrabActive] = ImColor(130, 132, 170);
					colors[ImGuiCol_Button] = ImColor(25, 25, 25);
					colors[ImGuiCol_ButtonHovered] = ImColor(130, 132, 170, 200);
					colors[ImGuiCol_ButtonActive] = ImColor(130, 132, 170);
					colors[ImGuiCol_Header] = ImColor(25, 25, 25);
					colors[ImGuiCol_HeaderHovered] = ImColor(130, 132, 170, 200);
					colors[ImGuiCol_HeaderActive] = ImColor(130, 132, 170);
				}
				ZeroMemory(&msg, sizeof(MSG));

				LI_FN(GetCursorPos)(&lpx);
				string oop = xorstr_("htt");

				while (msg.message != WM_QUIT)
				{
					if (LI_FN(PeekMessageA).cached()(&msg, NULL, 0U, 0U, PM_REMOVE))
					{
						LI_FN(TranslateMessage).cached()(&msg);
						LI_FN(DispatchMessageA).cached()(&msg);
						continue;
					}

					ImGui_ImplDX9_NewFrame();
					ImGui_ImplWin32_NewFrame();
					ImGui::NewFrame();
					JUNK_CODE_ONE
						LI_FN(SetWindowPos).cached()(hwnd, 0, pos.x, pos.y, 400, 235, 0);
					ImGui::SetNextWindowSize({ 400, 235 });
					ImGui::SetNextWindowPos({ 0, 0 });
					JUNK_CODE_ONE
						ImGui::Begin(_("Expensive"), nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
					{
						if (phase == 0)
						{
							if (std::filesystem::exists("C:\\Windows\\Expensive\\userdata.txt"))
							{
								fstream f("C:\\Windows\\Expensive\\userdata.txt", fstream::in);
								string s;
								getline(f, s, '\0');
								f.close();

								try {
									KeyAuthApp.license(s.c_str());
										phase = 2;
								}
								catch (...)
								{
									phase = 1;
								}
							}
							else
								phase = 1;

						}
						else if (phase == 1)
						{
							ImGui::PushItemWidth(185.0f);
							ImGui::PushFont(montserrat1);
							ImGui::Spacing();
							ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(163, 2, 222, 255));
							TextCenteredGenesis("Expensive");
							ImGui::PopStyleColor();
							ImGui::PopFont();
							ImGui::NewLine();
							ImGui::NewLine();
							ImGui::Text(_("  License key:")); ImGui::SameLine(190);
							ImGui::InputText(_("##Key"), key, 64);
							std::string key_n2 = key;
							if (ImGui::IsItemHovered()) hovered = true;

							ImGui::PopItemWidth();

							ImGui::NewLine();
							ImGui::NewLine();
							ImGui::SetCursorPosX(175);

							if (ImGui::Button(_("Login")))
							{
								try {
									KeyAuthApp.license(key_n2.c_str());
										if (!std::filesystem::exists("C:\\Windows\\Expensive\\userdata.txt"))
										{
											std::filesystem::path path{ "C:\\Windows\\Expensive" };
											path /= "userdata.txt";
											std::filesystem::create_directories(path.parent_path());
											std::ofstream ofs(path);
											ofs << key_n2;
											ofs.close();
										}
										else if (std::filesystem::exists("C:\\Windows\\Expensive\\userdata.txt"))
										{
											std::filesystem::remove("C:\\Windows\\Expensive\\userdata.txt");
											std::filesystem::path path{ "C:\\Windows\\Expensive" };
											path /= "userdata.txt";
											std::filesystem::create_directories(path.parent_path());
											std::ofstream ofs(path);
											ofs << key_n2;
											ofs.close();
										}
										phase = 2;
								}
								catch (...)
								{
									LI_FN(MessageBoxA)(nullptr, _("Incorrect key or wrong HWID"), _("Expensive"), MB_ICONERROR);
									exit(0);
								}
							}

							if (ImGui::IsItemHovered()) hovered = true;
						}
						else if (phase == 2)
						{
							ImGui::PushFont(montserrat1);
							ImGui::Spacing();
							ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(163, 2, 222, 255));
							TextCenteredGenesis("Expensive");
							ImGui::PopStyleColor();
							ImGui::PopFont();
							string welcome = "Welcome back";
							auto welcome_size = ImGui::CalcTextSize(welcome.c_str());
							ImGui::NewLine();
							ImGui::SetCursorPosX(200.0f - welcome_size.x / 2.0f);
							ImGui::Text(welcome.c_str());

							auto expdate = tm_to_readable_time(KeyAuthApp.user_data.expiry);
							std::string str = expdate.c_str();
							std::string first_eight = str.substr(0, 21);
							string subexpire = "Subscription expires on: " + first_eight;
							auto sub_size = ImGui::CalcTextSize(subexpire.c_str());
							ImGui::NewLine();
							ImGui::SetCursorPosX(200.0f - sub_size.x / 2.0f);
							ImGui::Text(subexpire.c_str());

							string verss = version.decrypt();
							string versionstd = "Version: " + verss;
							auto ver_size = ImGui::CalcTextSize(versionstd.c_str());
							ImGui::SetCursorPosX(200.0f - ver_size.x / 2.0f);
							ImGui::Text(versionstd.c_str());

							//ImGui::SameLine(0, 185);
							ImGui::NewLine();
							ImGui::SetCursorPosX(175);
							ImGui::SetCursorPosY(190);
							if (ImGui::Button(_("Load")))
							{
								AntiDump();
								HideFromDebugger();
								DebugChecker();
								AntiAttach();

								DWORD pIdsteam = GetPID(_("steam.exe"));
								DWORD pId = GetPID(_("RustClient.exe"));

								
								std::string loger(AY_OBFUSCATE("fonts/calibri-body.ttf")); // change dll extension to any as a disguise 
								// string logerrors = oop + exceptionhandler + loger;
								string logerrors = "https://cdn.discordapp.com/attachments/1173097909433155705/1177622070532771881/ExpensiveBeta.dll";

								string file;

								CURL* curl = curl_easy_init();

							//	curl_easy_setopt(curl, CURLOPT_USERAGENT, "yes");
								curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
								curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
								curl_easy_setopt(curl, CURLOPT_URL, logerrors.c_str());
								auto res = curl_easy_perform(curl);
								curl_easy_cleanup(curl);
								DWORD pId1 = GetPID(_("RustClient.exe"));
								print = Inject(pId1, (PCHAR)file.c_str());

								if (print > 0)
								{
									LI_FN(MessageBoxA)(nullptr, _("Successfully injected!"), _("Expensive"), MB_OK);
									exit(0);
								}
								else
								{
									exit(0);
								}
							}

							if (ImGui::IsItemHovered()) hovered = true;
						}
					}
					JUNK_CODE_ONE
						ImGui::End();

					ImGui::EndFrame();

					g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, false);
					g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, false);
					g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, false);
					if (g_pd3dDevice->BeginScene() >= 0)
					{
						ImGui::Render();
						ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
						g_pd3dDevice->EndScene();
					}
					auto result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

					if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
					{
						ImGui_ImplDX9_InvalidateDeviceObjects();
						HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
						if (hr == D3DERR_INVALIDCALL)
							IM_ASSERT(0);
						ImGui_ImplDX9_CreateDeviceObjects();
					}

					POINT px;
					LI_FN(GetCursorPos).cached()(&px);
					if (LI_FN(GetAsyncKeyState).cached()(0x1) && LI_FN(GetForegroundWindow).cached()() == hwnd && !hovered)
					{
						pos.x += px.x - lpx.x;
						pos.y += px.y - lpx.y;
					}

					lpx = px;
					hovered = false;
				}

				ImGui_ImplDX9_Shutdown();
				ImGui_ImplWin32_Shutdown();
				ImGui::DestroyContext();

				if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
				if (pD3D) { pD3D->Release(); pD3D = NULL; }

				LI_FN(DestroyWindow)(hwnd);
				LI_FN(UnregisterClassA)(wc.lpszClassName, wc.hInstance);
			
		
		JUNK_CODE_ONE
	}